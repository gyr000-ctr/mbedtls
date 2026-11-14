/**
 * \file hpke.c
 *
 * \brief Hybrid Public Key Encryption (HPKE, RFC 9180), Base mode.
 *
 * The implementation is written directly from the RFC 9180 pseudocode
 * and builds exclusively on PSA Crypto primitives (ECDH, HKDF, AEAD),
 * so it inherits their constant-time implementations for the sensitive
 * operations (shared secret, key material and tag verification).
 */
/*
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/hpke.h"

#if defined(MBEDTLS_HPKE_C)

#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#include "psa/crypto.h"

#include <string.h>

/* Magic values marking the lifecycle state of a context. They deliberately
 * are not predictable secrets and only guard against API misuse. */
#define HPKE_MAGIC_INIT    0x48U  /* initialized, not set up */
#define HPKE_MAGIC_LIVE    0x50U  /* set up, usable */

#define HPKE_DIRECTION_SENDER     1U
#define HPKE_DIRECTION_RECIPIENT  2U

/* RFC 9180 section 5.2: all supported AEADs have a 16-byte tag. */
#define HPKE_TAG_LEN 16U

/* Per-KEM parameters (RFC 9180 section 7.1). */
typedef struct {
    psa_ecc_family_t family;     /* PSA ECC family */
    uint16_t bits;               /* PSA key size in bits */
    uint8_t nenc;                /* Encapsulated key / public key length */
    uint8_t nsk;                 /* Private key length */
    uint8_t ndh;                 /* DH shared secret length */
    psa_algorithm_t hash;        /* KEM hash */
    uint8_t nh;                  /* KEM hash output length */
} hpke_kem_info_t;

/* Per-AEAD parameters (RFC 9180 section 7.3). */
typedef struct {
    psa_algorithm_t alg;         /* PSA AEAD algorithm */
    uint8_t nk;                  /* Key length */
    uint8_t nn;                  /* Nonce length */
    psa_key_type_t key_type;     /* PSA key type */
} hpke_aead_info_t;

static const hpke_kem_info_t hpke_kem_infos[] = {
    [MBEDTLS_HPKE_KEM_P256_HKDF_SHA256] = {
        PSA_ECC_FAMILY_SECP_R1, 256, 65, 32, 32, PSA_ALG_SHA_256, 32,
    },
    [MBEDTLS_HPKE_KEM_X25519_HKDF_SHA256] = {
        PSA_ECC_FAMILY_MONTGOMERY, 255, 32, 32, 32, PSA_ALG_SHA_256, 32,
    },
};

static const hpke_aead_info_t hpke_aead_infos[] = {
    [MBEDTLS_HPKE_AEAD_AES_128_GCM] = {
        PSA_ALG_GCM, 16, 12, PSA_KEY_TYPE_AES,
    },
    [MBEDTLS_HPKE_AEAD_AES_256_GCM] = {
        PSA_ALG_GCM, 32, 12, PSA_KEY_TYPE_AES,
    },
    [MBEDTLS_HPKE_AEAD_CHACHA20_POLY1305] = {
        PSA_ALG_CHACHA20_POLY1305, 32, 12, PSA_KEY_TYPE_CHACHA20,
    },
};

/* Largest temporary buffer this module ever allocates on the stack:
 * an HKDF PRK (Nh <= 48). */
#define HPKE_TMP_MAX 48U

void mbedtls_hpke_init(mbedtls_hpke_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    ctx->magic = HPKE_MAGIC_INIT;
}

void mbedtls_hpke_free(mbedtls_hpke_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    ctx->magic = HPKE_MAGIC_INIT;
}

int mbedtls_hpke_check_suite(uint16_t kem_id, uint16_t kdf_id,
                             uint16_t aead_id)
{
    if (kem_id != MBEDTLS_HPKE_KEM_P256_HKDF_SHA256 &&
        kem_id != MBEDTLS_HPKE_KEM_X25519_HKDF_SHA256) {
        return MBEDTLS_ERR_HPKE_NOT_SUPPORTED;
    }
    if (kdf_id != MBEDTLS_HPKE_KDF_HKDF_SHA256 &&
        kdf_id != MBEDTLS_HPKE_KDF_HKDF_SHA384) {
        return MBEDTLS_ERR_HPKE_NOT_SUPPORTED;
    }
    if (aead_id != MBEDTLS_HPKE_AEAD_AES_128_GCM &&
        aead_id != MBEDTLS_HPKE_AEAD_AES_256_GCM &&
        aead_id != MBEDTLS_HPKE_AEAD_CHACHA20_POLY1305) {
        return MBEDTLS_ERR_HPKE_NOT_SUPPORTED;
    }
    return 0;
}

static psa_algorithm_t hpke_kdf_hash(uint16_t kdf_id)
{
    if (kdf_id == MBEDTLS_HPKE_KDF_HKDF_SHA256) {
        return PSA_ALG_SHA_256;
    }
    return PSA_ALG_SHA_384;
}

static size_t hpke_kdf_nh(uint16_t kdf_id)
{
    return kdf_id == MBEDTLS_HPKE_KDF_HKDF_SHA256 ? 32U : 48U;
}

/*
 * HKDF-Extract (RFC 5869). The empty salt is represented explicitly as a
 * string of Nh zero bytes, as required by the HPKE labeled helpers.
 */
static int hpke_hkdf_extract(psa_algorithm_t hash, size_t nh,
                             const unsigned char *salt, size_t salt_len,
                             const unsigned char *ikm, size_t ikm_len,
                             unsigned char prk[HPKE_TMP_MAX])
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;
    int ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
    unsigned char zero_salt[MBEDTLS_HPKE_MAX_NH];

    if (salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, nh);
        salt = zero_salt;
        salt_len = nh;
    }

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            ikm, ikm_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_output_bytes(&op, prk, nh);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(zero_salt, sizeof(zero_salt));
    status = psa_key_derivation_abort(&op);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
    }
    return ret;
}

/*
 * HKDF-Expand (RFC 5869). \p length must be at most 255*Nh; the caller
 * validates this.
 */
static int hpke_hkdf_expand(psa_algorithm_t hash,
                            const unsigned char *prk, size_t prk_len,
                            const unsigned char *info, size_t info_len,
                            unsigned char *out, size_t length)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;
    int ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            prk, prk_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    if (info == NULL) {
        info = (const unsigned char *) "";
    }
    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, info_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_key_derivation_output_bytes(&op, out, length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = psa_key_derivation_abort(&op);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
    }
    return ret;
}

/* Build "HPKE-v1" || suite_id || label || ikm into \p out. */
static void hpke_labeled_ikm(const unsigned char *suite_id,
                             size_t suite_id_len,
                             const char *label, size_t label_len,
                             const unsigned char *ikm, size_t ikm_len,
                             unsigned char *out, size_t *out_len)
{
    static const unsigned char prefix[] = "HPKE-v1";
    size_t n = 0;

    memcpy(out + n, prefix, sizeof(prefix) - 1);
    n += sizeof(prefix) - 1;
    memcpy(out + n, suite_id, suite_id_len);
    n += suite_id_len;
    memcpy(out + n, label, label_len);
    n += label_len;
    if (ikm != NULL && ikm_len != 0) {
        memcpy(out + n, ikm, ikm_len);
        n += ikm_len;
    }
    *out_len = n;
}

/*
 * LabeledExtract (RFC 9180 section 4).
 * The labeled IKM is assembled in a fixed-size stack buffer; its maximum
 * size is bounded by the constant label/suite lengths and the KEM inputs
 * (Npk <= 65, Ndh <= 32), so no heap allocation is needed.
 */
static int hpke_labeled_extract(psa_algorithm_t hash, size_t nh,
                                const unsigned char *suite_id,
                                size_t suite_id_len,
                                const unsigned char *salt, size_t salt_len,
                                const char *label,
                                const unsigned char *ikm, size_t ikm_len,
                                unsigned char prk[HPKE_TMP_MAX])
{
    /* 6 (prefix) + 5 (suite_id) + 16 (longest label "shared_secret") +
     * 65 (largest IKM, a P-256 public key) + slack. */
    unsigned char labeled[6 + 5 + 16 + 65];
    size_t labeled_len = 0;

    hpke_labeled_ikm(suite_id, suite_id_len, label, strlen(label),
                     ikm, ikm_len, labeled, &labeled_len);
    return hpke_hkdf_extract(hash, nh, salt, salt_len,
                             labeled, labeled_len, prk);
}

/*
 * LabeledExpand (RFC 9180 section 4).
 */
static int hpke_labeled_expand(psa_algorithm_t hash, size_t nh,
                               const unsigned char *suite_id,
                               size_t suite_id_len,
                               const unsigned char *prk,
                               const char *label,
                               const unsigned char *info, size_t info_len,
                               unsigned char *out, size_t length)
{
    /* 2 (L) + 6 (prefix) + 5 (suite_id) + 12 (longest label "base_nonce")
     * + the KEM context / KSC (at most 1 + 2*Nh + 65*2 for the KEM case). */
    unsigned char labeled_info[2 + 6 + 5 + 12 + 1 + 2 * MBEDTLS_HPKE_MAX_NH
                               + 2 * MBEDTLS_HPKE_MAX_ENC_LEN];
    size_t n = 0;
    int ret;

    if (length > 255U * nh) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }

    labeled_info[n++] = (unsigned char) (length >> 8);
    labeled_info[n++] = (unsigned char) length;
    static const unsigned char prefix[] = "HPKE-v1";
    memcpy(labeled_info + n, prefix, sizeof(prefix) - 1);
    n += sizeof(prefix) - 1;
    memcpy(labeled_info + n, suite_id, suite_id_len);
    n += suite_id_len;
    size_t label_len = strlen(label);
    memcpy(labeled_info + n, label, label_len);
    n += label_len;
    if (info != NULL && info_len != 0) {
        memcpy(labeled_info + n, info, info_len);
        n += info_len;
    }

    ret = hpke_hkdf_expand(hash, prk, nh, labeled_info, n, out, length);
    mbedtls_platform_zeroize(labeled_info, sizeof(labeled_info));
    return ret;
}

static void hpke_kem_suite_id(uint16_t kem_id, unsigned char suite_id[5])
{
    suite_id[0] = 'K';
    suite_id[1] = 'E';
    suite_id[2] = 'M';
    suite_id[3] = (unsigned char) (kem_id >> 8);
    suite_id[4] = (unsigned char) kem_id;
}

static void hpke_hpke_suite_id(uint16_t kem_id, uint16_t kdf_id,
                               uint16_t aead_id, unsigned char suite_id[10])
{
    suite_id[0] = 'H';
    suite_id[1] = 'P';
    suite_id[2] = 'K';
    suite_id[3] = 'E';
    suite_id[4] = (unsigned char) (kem_id >> 8);
    suite_id[5] = (unsigned char) kem_id;
    suite_id[6] = (unsigned char) (kdf_id >> 8);
    suite_id[7] = (unsigned char) kdf_id;
    suite_id[8] = (unsigned char) (aead_id >> 8);
    suite_id[9] = (unsigned char) aead_id;
}

/*
 * Import an ECC private key for ECDH and perform the raw key agreement
 * with \p peer_pk. All key material is transient and destroyed before
 * returning.
 */
/*
 * Reject X25519 small-order public keys (RFC 7748 section 6.1). The PSA
 * backend does not reject all of them (some yield an all-zero shared
 * secret with PSA_SUCCESS), so HPKE must validate explicitly. The
 * comparison against the fixed table runs in constant time and only the
 * boolean result is used, so it does not leak which point was supplied.
 * Returns 1 if the key is a small-order point, 0 otherwise.
 */
static int hpke_x25519_is_small_order(const unsigned char pk[32])
{
    static const unsigned char small_order[][32] = {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE,
          0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
          0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x40, 0x29, 0x8C,
          0xD7, 0xF6, 0x9E, 0x60, 0x62, 0x55, 0xB3, 0x05 },
        { 0x5F, 0x1C, 0x85, 0x83, 0xC4, 0xBE, 0x47, 0x51,
          0xE9, 0xA9, 0x1C, 0x05, 0x0E, 0x60, 0x3B, 0x95,
          0x25, 0xF6, 0x72, 0x14, 0x63, 0xBF, 0xD6, 0x73,
          0x28, 0x09, 0x61, 0x9F, 0x4C, 0xAC, 0x4C, 0x7A },
        { 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
        { 0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
        { 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
    };
    /* Track whether any table entry matched: found is set to a non-zero
     * value without data-dependent branches. */
    int found = 0;

    for (size_t i = 0; i < sizeof(small_order) / sizeof(small_order[0]); i++) {
        int eq = mbedtls_ct_memcmp(pk, small_order[i], 32) == 0;
        found = found | eq;
    }
    return found != 0;
}

static int hpke_dh(const hpke_kem_info_t *kem_info,
                   const unsigned char *sk, size_t sk_len,
                   const unsigned char *peer_pk, size_t peer_pk_len,
                   unsigned char shared[MBEDTLS_HPKE_MAX_NH])
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    mbedtls_svc_key_id_t key_id = 0;
    psa_status_t status;
    size_t shared_len = 0;
    int ret;

    /* Explicit small-order validation for X25519 (see above). */
    if (kem_info->family == PSA_ECC_FAMILY_MONTGOMERY &&
        hpke_x25519_is_small_order(peer_pk)) {
        return MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY;
    }

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(kem_info->family));
    psa_set_key_bits(&attr, kem_info->bits);

    status = psa_import_key(&attr, sk, sk_len, &key_id);
    if (status != PSA_SUCCESS) {
        /* An invalid scalar (e.g. zero for Montgomery, out-of-range for
         * Weierstrass) is reported as an invalid argument. */
        ret = (status == PSA_ERROR_NOT_SUPPORTED) ?
              MBEDTLS_ERR_HPKE_NOT_SUPPORTED :
              MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY;
        goto cleanup;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id,
                                   peer_pk, peer_pk_len,
                                   shared, kem_info->ndh, &shared_len);
    if (status != PSA_SUCCESS) {
        ret = (status == PSA_ERROR_INVALID_ARGUMENT) ?
              MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY :
              MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
        goto cleanup;
    }
    if (shared_len != kem_info->ndh) {
        ret = MBEDTLS_ERR_HPKE_CORRUPTION_DETECTED;
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }
    if (ret != 0) {
        mbedtls_platform_zeroize(shared, kem_info->ndh);
    }
    return ret;
}

/* Compute the public key corresponding to an imported ECC private key. */
static int hpke_public_from_private(const hpke_kem_info_t *kem_info,
                                    const unsigned char *sk, size_t sk_len,
                                    unsigned char *pk, size_t pk_size,
                                    size_t *pk_len)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    mbedtls_svc_key_id_t key_id = 0;
    psa_status_t status;
    int ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE |
                            PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(kem_info->family));
    psa_set_key_bits(&attr, kem_info->bits);

    status = psa_import_key(&attr, sk, sk_len, &key_id);
    if (status != PSA_SUCCESS) {
        ret = (status == PSA_ERROR_NOT_SUPPORTED) ?
              MBEDTLS_ERR_HPKE_NOT_SUPPORTED :
              MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY;
        goto cleanup;
    }
    status = psa_export_public_key(key_id, pk, pk_size, pk_len);
    if (status != PSA_SUCCESS) {
        ret = (status == PSA_ERROR_BUFFER_TOO_SMALL) ?
              MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL :
              MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }
    return ret;
}

/*
 * ExtractAndExpand (RFC 9180 section 4.1): turn a DH value into the KEM
 * shared secret bound to \p kem_context.
 */
static int hpke_extract_and_expand(const hpke_kem_info_t *kem_info,
                                   uint16_t kem_id,
                                   const unsigned char *dh, size_t dh_len,
                                   const unsigned char *kem_context,
                                   size_t kem_context_len,
                                   unsigned char shared_secret[MBEDTLS_HPKE_MAX_NH])
{
    unsigned char suite_id[5];
    unsigned char eae_prk[HPKE_TMP_MAX];
    int ret;

    hpke_kem_suite_id(kem_id, suite_id);
    ret = hpke_labeled_extract(kem_info->hash, kem_info->nh, suite_id,
                               sizeof(suite_id), NULL, 0, "eae_prk",
                               dh, dh_len, eae_prk);
    if (ret != 0) {
        goto cleanup;
    }
    ret = hpke_labeled_expand(kem_info->hash, kem_info->nh, suite_id,
                              sizeof(suite_id), eae_prk, "shared_secret",
                              kem_context, kem_context_len,
                              shared_secret, kem_info->ndh);

cleanup:
    mbedtls_platform_zeroize(eae_prk, sizeof(eae_prk));
    return ret;
}

/*
 * KeySchedule (RFC 9180 section 5.1), Base mode (mode = 0, no PSK).
 * Fills the AEAD key, base nonce and exporter secret in \p ctx.
 */
static int hpke_key_schedule(mbedtls_hpke_context *ctx,
                             uint16_t kem_id,
                             uint16_t kdf_id, uint16_t aead_id,
                             const unsigned char *shared_secret,
                             size_t shared_secret_len,
                             const unsigned char *info, size_t info_len)
{
    const hpke_aead_info_t *aead = &hpke_aead_infos[aead_id];
    psa_algorithm_t hash = hpke_kdf_hash(kdf_id);
    size_t nh = hpke_kdf_nh(kdf_id);
    unsigned char suite_id[10];
    /* psk_id_hash(48) + info_hash(48) + mode byte; KSC is fed directly
     * into the expand calls and never exceeds this size. */
    unsigned char psk_id_hash[HPKE_TMP_MAX];
    unsigned char info_hash[HPKE_TMP_MAX];
    unsigned char secret[HPKE_TMP_MAX];
    unsigned char ksc[1 + 2 * MBEDTLS_HPKE_MAX_NH];
    size_t ksc_len = 0;
    int ret;

    hpke_hpke_suite_id(kem_id, kdf_id, aead_id, suite_id);

    /* Base mode: psk = "", psk_id = "". */
    ret = hpke_labeled_extract(hash, nh, suite_id, sizeof(suite_id),
                               NULL, 0, "psk_id_hash",
                               NULL, 0, psk_id_hash);
    if (ret != 0) {
        goto cleanup;
    }
    ret = hpke_labeled_extract(hash, nh, suite_id, sizeof(suite_id),
                               NULL, 0, "info_hash",
                               info, info_len, info_hash);
    if (ret != 0) {
        goto cleanup;
    }
    ksc[ksc_len++] = 0; /* mode_base */
    memcpy(ksc + ksc_len, psk_id_hash, nh);
    ksc_len += nh;
    memcpy(ksc + ksc_len, info_hash, nh);
    ksc_len += nh;

    ret = hpke_labeled_extract(hash, nh, suite_id, sizeof(suite_id),
                               shared_secret, shared_secret_len,
                               "secret", NULL, 0, secret);
    if (ret != 0) {
        goto cleanup;
    }

    ret = hpke_labeled_expand(hash, nh, suite_id, sizeof(suite_id), secret,
                              "key", ksc, ksc_len,
                              ctx->key, aead->nk);
    if (ret != 0) {
        goto cleanup;
    }
    ctx->key_len = (uint8_t) aead->nk;

    ret = hpke_labeled_expand(hash, nh, suite_id, sizeof(suite_id), secret,
                              "base_nonce", ksc, ksc_len,
                              ctx->base_nonce, aead->nn);
    if (ret != 0) {
        goto cleanup;
    }
    ctx->nonce_len = (uint8_t) aead->nn;

    ret = hpke_labeled_expand(hash, nh, suite_id, sizeof(suite_id), secret,
                              "exp", ksc, ksc_len,
                              ctx->exporter_secret, nh);
    if (ret != 0) {
        goto cleanup;
    }
    ctx->nh = (uint8_t) nh;

cleanup:
    mbedtls_platform_zeroize(psk_id_hash, sizeof(psk_id_hash));
    mbedtls_platform_zeroize(info_hash, sizeof(info_hash));
    mbedtls_platform_zeroize(secret, sizeof(secret));
    mbedtls_platform_zeroize(ksc, sizeof(ksc));
    return ret;
}

/* Validate the common setup arguments and fill the static KEM data. */
static int hpke_setup_prepare(mbedtls_hpke_context *ctx,
                              uint16_t kem_id, uint16_t kdf_id,
                              uint16_t aead_id,
                              const hpke_kem_info_t **kem_info,
                              const unsigned char *info, size_t info_len)
{
    int ret;

    if (ctx == NULL || kem_info == NULL) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (ctx->magic != HPKE_MAGIC_INIT) {
        return MBEDTLS_ERR_HPKE_BAD_STATE;
    }
    ret = mbedtls_hpke_check_suite(kem_id, kdf_id, aead_id);
    if (ret != 0) {
        return ret;
    }
    if (info == NULL && info_len != 0) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }

    *kem_info = &hpke_kem_infos[kem_id];
    return 0;
}

int mbedtls_hpke_setup_base_s(mbedtls_hpke_context *ctx,
                              uint16_t kem_id, uint16_t kdf_id,
                              uint16_t aead_id,
                              const unsigned char *pk_r, size_t pk_r_len,
                              const unsigned char *info, size_t info_len,
                              const unsigned char *ephemeral_sk,
                              size_t ephemeral_sk_len,
                              unsigned char *enc, size_t enc_size,
                              size_t *enc_len)
{
    const hpke_kem_info_t *kem_info;
    unsigned char dh[MBEDTLS_HPKE_MAX_NH];
    unsigned char shared_secret[MBEDTLS_HPKE_MAX_NH];
    unsigned char pk_e[MBEDTLS_HPKE_MAX_ENC_LEN];
    /* kem_context = pk_e || pk_r, at most 2*Nenc. */
    unsigned char kem_context[2 * MBEDTLS_HPKE_MAX_ENC_LEN];
    size_t pk_e_len = 0;
    int ret;

    ret = hpke_setup_prepare(ctx, kem_id, kdf_id, aead_id,
                             &kem_info, info, info_len);
    if (ret != 0) {
        return ret;
    }
    if (pk_r == NULL || pk_r_len != kem_info->nenc ||
        ephemeral_sk == NULL || ephemeral_sk_len != kem_info->nsk ||
        enc == NULL || enc_len == NULL) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (enc_size < kem_info->nenc) {
        return MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
    }

    /* Encap with a caller-supplied ephemeral key pair. */
    ret = hpke_public_from_private(kem_info, ephemeral_sk, ephemeral_sk_len,
                                   pk_e, sizeof(pk_e), &pk_e_len);
    if (ret != 0) {
        goto cleanup;
    }
    if (pk_e_len != kem_info->nenc) {
        ret = MBEDTLS_ERR_HPKE_CORRUPTION_DETECTED;
        goto cleanup;
    }

    ret = hpke_dh(kem_info, ephemeral_sk, ephemeral_sk_len,
                  pk_r, pk_r_len, dh);
    if (ret != 0) {
        goto cleanup;
    }

    memcpy(kem_context, pk_e, pk_e_len);
    memcpy(kem_context + pk_e_len, pk_r, pk_r_len);
    ret = hpke_extract_and_expand(kem_info, kem_id, dh, kem_info->ndh,
                                  kem_context, pk_e_len + pk_r_len,
                                  shared_secret);
    if (ret != 0) {
        goto cleanup;
    }
    ret = hpke_key_schedule(ctx, kem_id, kdf_id, aead_id,
                            shared_secret, kem_info->ndh, info, info_len);
    if (ret != 0) {
        goto cleanup;
    }

    memcpy(enc, pk_e, pk_e_len);
    *enc_len = pk_e_len;

    ctx->kem_id = (uint16_t) kem_id;
    ctx->kdf_id = (uint16_t) kdf_id;
    ctx->aead_id = (uint16_t) aead_id;
    ctx->seq = 0;
    ctx->direction = HPKE_DIRECTION_SENDER;
    ctx->magic = HPKE_MAGIC_LIVE;

cleanup:
    mbedtls_platform_zeroize(dh, sizeof(dh));
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    mbedtls_platform_zeroize(pk_e, sizeof(pk_e));
    mbedtls_platform_zeroize(kem_context, sizeof(kem_context));
    if (ret != 0) {
        mbedtls_hpke_free(ctx);
    }
    return ret;
}

int mbedtls_hpke_setup_base_r(mbedtls_hpke_context *ctx,
                              uint16_t kem_id, uint16_t kdf_id,
                              uint16_t aead_id,
                              const unsigned char *enc, size_t enc_len,
                              const unsigned char *sk_r, size_t sk_r_len,
                              const unsigned char *info, size_t info_len)
{
    const hpke_kem_info_t *kem_info;
    unsigned char dh[MBEDTLS_HPKE_MAX_NH];
    unsigned char shared_secret[MBEDTLS_HPKE_MAX_NH];
    unsigned char pk_r[MBEDTLS_HPKE_MAX_ENC_LEN];
    unsigned char kem_context[2 * MBEDTLS_HPKE_MAX_ENC_LEN];
    size_t pk_r_len = 0;
    int ret;

    ret = hpke_setup_prepare(ctx, kem_id, kdf_id, aead_id,
                             &kem_info, info, info_len);
    if (ret != 0) {
        return ret;
    }
    if (enc == NULL || enc_len != kem_info->nenc ||
        sk_r == NULL || sk_r_len != kem_info->nsk) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }

    /* Derive pk_r so the kem_context (enc || pk_r) matches the sender's. */
    ret = hpke_public_from_private(kem_info, sk_r, sk_r_len,
                                   pk_r, sizeof(pk_r), &pk_r_len);
    if (ret != 0) {
        goto cleanup;
    }
    if (pk_r_len != kem_info->nenc) {
        ret = MBEDTLS_ERR_HPKE_CORRUPTION_DETECTED;
        goto cleanup;
    }

    /* Decap: DH(sk_r, enc). An invalid enc is rejected here. */
    ret = hpke_dh(kem_info, sk_r, sk_r_len, enc, enc_len, dh);
    if (ret != 0) {
        goto cleanup;
    }

    memcpy(kem_context, enc, enc_len);
    memcpy(kem_context + enc_len, pk_r, pk_r_len);
    ret = hpke_extract_and_expand(kem_info, kem_id, dh, kem_info->ndh,
                                  kem_context, enc_len + pk_r_len,
                                  shared_secret);
    if (ret != 0) {
        goto cleanup;
    }

    ret = hpke_key_schedule(ctx, kem_id, kdf_id, aead_id,
                            shared_secret, kem_info->ndh, info, info_len);
    if (ret != 0) {
        goto cleanup;
    }

    ctx->kem_id = (uint16_t) kem_id;
    ctx->kdf_id = (uint16_t) kdf_id;
    ctx->aead_id = (uint16_t) aead_id;
    ctx->seq = 0;
    ctx->direction = HPKE_DIRECTION_RECIPIENT;
    ctx->magic = HPKE_MAGIC_LIVE;

cleanup:
    mbedtls_platform_zeroize(dh, sizeof(dh));
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    mbedtls_platform_zeroize(pk_r, sizeof(pk_r));
    mbedtls_platform_zeroize(kem_context, sizeof(kem_context));
    if (ret != 0) {
        mbedtls_hpke_free(ctx);
    }
    return ret;
}

/* Compute the per-message nonce: base_nonce XOR I2OSP(seq, Nn). */
static void hpke_compute_nonce(const mbedtls_hpke_context *ctx,
                               unsigned char nonce[MBEDTLS_HPKE_MAX_NONCE_LEN])
{
    uint64_t seq = ctx->seq;
    size_t i;

    memcpy(nonce, ctx->base_nonce, ctx->nonce_len);
    for (i = 0; i < ctx->nonce_len; i++) {
        size_t shift = (ctx->nonce_len - 1 - i) * 8;
        if (shift >= 64) {
            /* seq cannot contribute to bytes beyond its width. */
            continue;
        }
        nonce[i] ^= (unsigned char) (seq >> shift);
    }
}

/* RFC 9180 section 5.2: the sequence number must not overflow the nonce. */
static int hpke_check_seq(const mbedtls_hpke_context *ctx)
{
    if (ctx->magic != HPKE_MAGIC_LIVE) {
        return MBEDTLS_ERR_HPKE_BAD_STATE;
    }
    /* With Nn <= 12 the bound 2^(8*Nn)-1 does not fit in uint64 when
     * Nn >= 8; the practical limit is then UINT64_MAX. Checking the top
     * bytes of the nonce width covers both cases. */
    if (ctx->nonce_len <= 8 &&
        ctx->seq >= ((uint64_t) 1 << (8 * ctx->nonce_len))) {
        return MBEDTLS_ERR_HPKE_MESSAGE_LIMIT;
    }
    if (ctx->seq == UINT64_MAX) {
        return MBEDTLS_ERR_HPKE_MESSAGE_LIMIT;
    }
    return 0;
}

/* Import the context's AEAD key transiently. The key handle is destroyed
 * by the caller after the operation. */
static int hpke_import_aead_key(const mbedtls_hpke_context *ctx,
                                psa_key_usage_t usage,
                                mbedtls_svc_key_id_t *key_id)
{
    const hpke_aead_info_t *aead = &hpke_aead_infos[ctx->aead_id];
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_status_t status;

    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, aead->alg);
    psa_set_key_type(&attr, aead->key_type);
    psa_set_key_bits(&attr, (size_t) ctx->key_len * 8U);

    status = psa_import_key(&attr, ctx->key, ctx->key_len, key_id);
    if (status != PSA_SUCCESS) {
        *key_id = 0;
        return MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
    }
    return 0;
}

int mbedtls_hpke_seal(mbedtls_hpke_context *ctx,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *plaintext, size_t plaintext_len,
                      unsigned char *ciphertext, size_t ciphertext_size,
                      size_t *ciphertext_len)
{
    const hpke_aead_info_t *aead;
    mbedtls_svc_key_id_t key_id = 0;
    psa_status_t status;
    unsigned char nonce[MBEDTLS_HPKE_MAX_NONCE_LEN];
    size_t out_len = 0;
    int ret;

    if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (aad == NULL && aad_len != 0) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (plaintext == NULL && plaintext_len != 0) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    ret = hpke_check_seq(ctx);
    if (ret != 0) {
        return ret;
    }
    if (ctx->direction != HPKE_DIRECTION_SENDER) {
        return MBEDTLS_ERR_HPKE_BAD_STATE;
    }
    /* Guard against plaintext_len + tag overflowing size_t. */
    if (plaintext_len > SIZE_MAX - HPKE_TAG_LEN ||
        ciphertext_size < plaintext_len + HPKE_TAG_LEN) {
        return MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
    }
    aead = &hpke_aead_infos[ctx->aead_id];

    ret = hpke_import_aead_key(ctx, PSA_KEY_USAGE_ENCRYPT, &key_id);
    if (ret != 0) {
        return ret;
    }

    hpke_compute_nonce(ctx, nonce);
    status = psa_aead_encrypt(key_id, aead->alg, nonce, ctx->nonce_len,
                              aad, aad_len, plaintext, plaintext_len,
                              ciphertext, ciphertext_size, &out_len);
    if (status != PSA_SUCCESS) {
        ret = (status == PSA_ERROR_BUFFER_TOO_SMALL) ?
              MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL :
              MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
        goto cleanup;
    }

    *ciphertext_len = out_len;
    ctx->seq++;
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(nonce, sizeof(nonce));
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }
    return ret;
}

int mbedtls_hpke_open(mbedtls_hpke_context *ctx,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *ciphertext,
                      size_t ciphertext_len,
                      unsigned char *plaintext, size_t plaintext_size,
                      size_t *plaintext_len)
{
    const hpke_aead_info_t *aead;
    mbedtls_svc_key_id_t key_id = 0;
    psa_status_t status;
    unsigned char nonce[MBEDTLS_HPKE_MAX_NONCE_LEN];
    size_t out_len = 0;
    int ret;

    if (ctx == NULL || ciphertext == NULL || plaintext == NULL ||
        plaintext_len == NULL) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (aad == NULL && aad_len != 0) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (ciphertext_len < HPKE_TAG_LEN) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    ret = hpke_check_seq(ctx);
    if (ret != 0) {
        return ret;
    }
    if (ctx->direction != HPKE_DIRECTION_RECIPIENT) {
        return MBEDTLS_ERR_HPKE_BAD_STATE;
    }
    if (plaintext_size < ciphertext_len - HPKE_TAG_LEN) {
        return MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
    }
    aead = &hpke_aead_infos[ctx->aead_id];

    ret = hpke_import_aead_key(ctx, PSA_KEY_USAGE_DECRYPT, &key_id);
    if (ret != 0) {
        return ret;
    }

    hpke_compute_nonce(ctx, nonce);
    status = psa_aead_decrypt(key_id, aead->alg, nonce, ctx->nonce_len,
                              aad, aad_len, ciphertext, ciphertext_len,
                              plaintext, plaintext_size, &out_len);
    if (status != PSA_SUCCESS) {
        /* The AEAD driver verifies the tag in constant time and, on a
         * mismatch, zeroizes the plaintext region before reporting, so
         * no recovered plaintext is left in the output buffer. Map the
         * result to the distinguishable authentication error. */
        if (status == PSA_ERROR_INVALID_SIGNATURE) {
            ret = MBEDTLS_ERR_HPKE_AUTH_FAILED;
        } else if (status == PSA_ERROR_BUFFER_TOO_SMALL) {
            ret = MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
        } else {
            ret = MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED;
        }
        goto cleanup;
    }

    *plaintext_len = out_len;
    /* Sequence advances only on success, so a failed Open() does not
     * desynchronize the context. */
    ctx->seq++;
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(nonce, sizeof(nonce));
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }
    return ret;
}

int mbedtls_hpke_export(mbedtls_hpke_context *ctx,
                        const unsigned char *exporter_context,
                        size_t exporter_context_len,
                        size_t length,
                        unsigned char *exported)
{
    psa_algorithm_t hash;
    unsigned char suite_id[10];

    if (ctx == NULL || exported == NULL) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (exporter_context == NULL && exporter_context_len != 0) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (ctx->magic != HPKE_MAGIC_LIVE) {
        return MBEDTLS_ERR_HPKE_BAD_STATE;
    }
    if (length > 255U * ctx->nh) {
        return MBEDTLS_ERR_HPKE_BAD_INPUT_DATA;
    }
    if (length == 0) {
        return 0;
    }

    hash = hpke_kdf_hash(ctx->kdf_id);
    hpke_hpke_suite_id(ctx->kem_id, ctx->kdf_id, ctx->aead_id, suite_id);

    return hpke_labeled_expand(hash, ctx->nh, suite_id, sizeof(suite_id),
                               ctx->exporter_secret, "sec",
                               exporter_context, exporter_context_len,
                               exported, length);
}

int mbedtls_hpke_message_limit(const mbedtls_hpke_context *ctx)
{
    if (ctx == NULL || ctx->magic != HPKE_MAGIC_LIVE) {
        return 1;
    }
    return hpke_check_seq(ctx) != 0;
}

#endif /* MBEDTLS_HPKE_C */
