/**
 * \file hpke.h
 *
 * \brief Hybrid Public Key Encryption (HPKE, RFC 9180), Base mode.
 *
 * HPKE provides public-key encryption of small messages (and an
 * authenticated key-exchange / export interface) built from a KEM
 * (key encapsulation mechanism), a KDF and an AEAD. This implementation
 * supports the Base mode only (no PSK or authenticated modes) with the
 * following cipher suites:
 *
 * - KEM: DHKEM(P-256, HKDF-SHA256) and DHKEM(X25519, HKDF-SHA256),
 * - KDF: HKDF-SHA256 and HKDF-SHA384,
 * - AEAD: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
 *
 * A typical sender flow is:
 * 1. mbedtls_hpke_setup_base_s() with the recipient's public key;
 * 2. zero or more mbedtls_hpke_seal() calls on the returned context;
 * 3. optionally mbedtls_hpke_export() calls;
 * 4. mbedtls_hpke_free().
 *
 * A typical recipient flow is:
 * 1. mbedtls_hpke_setup_base_r() with the received encapsulated key and
 *    the recipient's private key;
 * 2. the same number of mbedtls_hpke_open() calls, in the same order;
 * 3. optionally mbedtls_hpke_export() calls;
 * 4. mbedtls_hpke_free().
 *
 * All functions in this module are additive: no pre-existing Mbed TLS
 * interface is changed.
 */
/*
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_HPKE_H
#define MBEDTLS_HPKE_H

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#if defined(MBEDTLS_HPKE_C)

/**
 * \name HPKE module error codes
 * \{
 */
#define MBEDTLS_ERR_HPKE_BAD_INPUT_DATA       -0x4880  /**< A parameter is missing, has the wrong length or is otherwise invalid. */
#define MBEDTLS_ERR_HPKE_NOT_SUPPORTED        -0x4800  /**< The requested KEM, KDF or AEAD identifier is not supported. */
#define MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY   -0x4900  /**< A public key (recipient key or encapsulated key) is invalid for the KEM. */
#define MBEDTLS_ERR_HPKE_AUTH_FAILED          -0x4980  /**< AEAD decryption failed: the tag does not authenticate. */
#define MBEDTLS_ERR_HPKE_MESSAGE_LIMIT        -0x4A00  /**< The sequence number of the context has reached its limit. */
#define MBEDTLS_ERR_HPKE_BAD_STATE            -0x4A80  /**< The context is not in a state that permits this operation (wrong direction or reused context). */
#define MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL     -0x4B00  /**< An output buffer is too small for the result. */
#define MBEDTLS_ERR_HPKE_HW_ACCEL_FAILED      -0x4B80  /**< The underlying cryptographic accelerator failed. */
#define MBEDTLS_ERR_HPKE_CORRUPTION_DETECTED  -0x4C00  /**< An internal inconsistency was detected. */
/* \} name */

/**
 * \name KEM identifiers (RFC 9180 section 7.1)
 * \{
 */
#define MBEDTLS_HPKE_KEM_P256_HKDF_SHA256      0x0010U /**< DHKEM(P-256, HKDF-SHA256). */
#define MBEDTLS_HPKE_KEM_X25519_HKDF_SHA256    0x0020U /**< DHKEM(X25519, HKDF-SHA256). */
/* \} name */

/**
 * \name KDF identifiers (RFC 9180 section 7.2)
 * \{
 */
#define MBEDTLS_HPKE_KDF_HKDF_SHA256           0x0001U /**< HKDF-SHA256. */
#define MBEDTLS_HPKE_KDF_HKDF_SHA384           0x0002U /**< HKDF-SHA384. */
/* \} name */

/**
 * \name AEAD identifiers (RFC 9180 section 7.3)
 * \{
 */
#define MBEDTLS_HPKE_AEAD_AES_128_GCM          0x0001U /**< AES-128-GCM. */
#define MBEDTLS_HPKE_AEAD_AES_256_GCM          0x0002U /**< AES-256-GCM. */
#define MBEDTLS_HPKE_AEAD_CHACHA20_POLY1305    0x0003U /**< ChaCha20-Poly1305. */
/* \} name */

/** Maximum length, in bytes, of an encapsulated key (\c enc) over the
 * supported KEMs (65 bytes for the uncompressed P-256 point). */
#define MBEDTLS_HPKE_MAX_ENC_LEN               65

/** Maximum AEAD key length, in bytes, over the supported AEADs. */
#define MBEDTLS_HPKE_MAX_KEY_LEN               32

/** Maximum AEAD nonce length, in bytes, over the supported AEADs. */
#define MBEDTLS_HPKE_MAX_NONCE_LEN             12

/** Maximum hash length (\c Nh), in bytes, over the supported KDFs
 * (SHA-384 produces 48 bytes). */
#define MBEDTLS_HPKE_MAX_NH                    48

/** AEAD authentication tag length, in bytes, shared by all supported
 * AEADs. */
#define MBEDTLS_HPKE_TAG_LEN                   16

/** Maximum length, in bytes, that can be requested from
 * mbedtls_hpke_export() (255 * Nh, RFC 9180 section 5.3 limits the
 * value to 255*Nh where Nh is at most 48 here). */
#define MBEDTLS_HPKE_MAX_EXPORT_LEN            (255U * MBEDTLS_HPKE_MAX_NH)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief HPKE sender or recipient context.
 *
 * An initialized context is bound to one direction: a context returned
 * by mbedtls_hpke_setup_base_s() only supports mbedtls_hpke_seal() and
 * one returned by mbedtls_hpke_setup_base_r() only supports
 * mbedtls_hpke_open(). mbedtls_hpke_export() is valid for either.
 *
 * The contents of this structure are internal and may change between
 * versions. Applications must not access fields directly.
 */
typedef struct mbedtls_hpke_context {
    uint8_t key[MBEDTLS_HPKE_MAX_KEY_LEN];      /*!< AEAD key. */
    uint8_t base_nonce[MBEDTLS_HPKE_MAX_NONCE_LEN]; /*!< Base nonce. */
    uint8_t exporter_secret[MBEDTLS_HPKE_MAX_NH]; /*!< Exporter secret. */
    uint64_t seq;                               /*!< Next sequence number. */
    uint16_t kem_id;                            /*!< KEM identifier. */
    uint16_t kdf_id;                            /*!< KDF identifier. */
    uint16_t aead_id;                           /*!< AEAD identifier. */
    uint8_t key_len;                            /*!< AEAD key length Nk. */
    uint8_t nonce_len;                          /*!< AEAD nonce length Nn. */
    uint8_t nh;                                 /*!< Hash length Nh. */
    uint8_t direction;                          /*!< 0: unused, 1: sender, 2: recipient. */
    uint8_t magic;                              /*!< State-validation marker. */
} mbedtls_hpke_context;

/**
 * \brief Initialize an HPKE context.
 *
 * Makes the context ready for mbedtls_hpke_setup_base_s(),
 * mbedtls_hpke_setup_base_r() or mbedtls_hpke_free().
 *
 * \param ctx   The context to initialize. May be NULL, in which case
 *              this call does nothing.
 */
void mbedtls_hpke_init(mbedtls_hpke_context *ctx);

/**
 * \brief Check whether an HPKE cipher suite is supported.
 *
 * \param kem_id    KEM identifier, one of the MBEDTLS_HPKE_KEM_* macros.
 * \param kdf_id    KDF identifier, one of the MBEDTLS_HPKE_KDF_* macros.
 * \param aead_id   AEAD identifier, one of the MBEDTLS_HPKE_AEAD_* macros.
 *
 * \return          \c 0 if the suite is supported, otherwise
 *                  #MBEDTLS_ERR_HPKE_NOT_SUPPORTED.
 */
int mbedtls_hpke_check_suite(uint16_t kem_id, uint16_t kdf_id,
                             uint16_t aead_id);

/**
 * \brief HPKE SetupBaseS (RFC 9180 section 5.1.1), with a caller-supplied
 *        ephemeral key pair.
 *
 * Generates the encapsulated key \p enc and derives the sender context.
 * The ephemeral private key is provided by the caller instead of being
 * generated internally so that the operation is fully deterministic and
 * testable. The caller is responsible for obtaining \p ephemeral_sk from
 * a secure random source for real deployments.
 *
 * On failure the context is left uninitialized (as after
 * mbedtls_hpke_init()) and no secret material is retained in it.
 *
 * \param ctx           The context to set up. Must have been initialized
 *                      with mbedtls_hpke_init() and not currently be in
 *                      use.
 * \param kem_id        KEM identifier.
 * \param kdf_id        KDF identifier.
 * \param aead_id       AEAD identifier.
 * \param pk_r          The recipient's public key. For P-256 this is the
 *                      65-byte uncompressed point; for X25519 the 32-byte
 *                      raw public key.
 * \param pk_r_len      Length of \p pk_r in bytes.
 * \param info          The \c info parameter (context binding). May be
 *                      \c NULL if \p info_len is 0.
 * \param info_len      Length of \p info in bytes.
 * \param ephemeral_sk  The ephemeral sender private key: 32 bytes for
 *                      either supported KEM (for P-256 it is the big-endian
 *                      scalar).
 * \param ephemeral_sk_len  Length of \p ephemeral_sk in bytes.
 * \param enc           Output buffer for the encapsulated key.
 * \param enc_size      Size of the \p enc buffer. Must be at least the
 *                      KEM's \c Nenc (32 for X25519, 65 for P-256);
 *                      #MBEDTLS_HPKE_MAX_ENC_LEN always suffices.
 * \param enc_len       On success, the number of bytes written to \p enc.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_HPKE_NOT_SUPPORTED if a suite
 *                      identifier is unknown.
 * \return              #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA on a bad length
 *                      or missing parameter.
 * \return              #MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY if \p pk_r is
 *                      not a valid public key for the KEM.
 * \return              #MBEDTLS_ERR_HPKE_BAD_STATE if \p ctx is already
 *                      set up.
 * \return              #MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL if \p enc_size
 *                      is too small.
 * \return              Another negative error code on cryptographic failure.
 */
int mbedtls_hpke_setup_base_s(mbedtls_hpke_context *ctx,
                              uint16_t kem_id, uint16_t kdf_id,
                              uint16_t aead_id,
                              const unsigned char *pk_r, size_t pk_r_len,
                              const unsigned char *info, size_t info_len,
                              const unsigned char *ephemeral_sk,
                              size_t ephemeral_sk_len,
                              unsigned char *enc, size_t enc_size,
                              size_t *enc_len);

/**
 * \brief HPKE SetupBaseR (RFC 9180 section 5.1.2).
 *
 * Derives the recipient context from the encapsulated key received from
 * the sender and the recipient's private key.
 *
 * On failure the context is left uninitialized and no secret material is
 * retained in it.
 *
 * \param ctx           The context to set up. Must have been initialized
 *                      with mbedtls_hpke_init() and not currently be in
 *                      use.
 * \param kem_id        KEM identifier.
 * \param kdf_id        KDF identifier.
 * \param aead_id       AEAD identifier.
 * \param enc           The encapsulated key received from the sender
 *                      (\c Nenc bytes: 32 for X25519, 65 for P-256).
 * \param enc_len       Length of \p enc in bytes.
 * \param sk_r          The recipient's private key (32 bytes for either
 *                      supported KEM; for P-256 the big-endian scalar).
 * \param sk_r_len      Length of \p sk_r in bytes.
 * \param info          The \c info parameter. Must be identical to the
 *                      sender's \c info. May be \c NULL if \p info_len
 *                      is 0.
 * \param info_len      Length of \p info in bytes.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_HPKE_NOT_SUPPORTED if a suite
 *                      identifier is unknown.
 * \return              #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA on a bad length
 *                      or missing parameter.
 * \return              #MBEDTLS_ERR_HPKE_INVALID_PUBLIC_KEY if \p enc is
 *                      not a valid public key for the KEM.
 * \return              #MBEDTLS_ERR_HPKE_BAD_STATE if \p ctx is already
 *                      set up.
 * \return              Another negative error code on cryptographic failure.
 */
int mbedtls_hpke_setup_base_r(mbedtls_hpke_context *ctx,
                              uint16_t kem_id, uint16_t kdf_id,
                              uint16_t aead_id,
                              const unsigned char *enc, size_t enc_len,
                              const unsigned char *sk_r, size_t sk_r_len,
                              const unsigned char *info, size_t info_len);

/**
 * \brief HPKE Seal (RFC 9180 section 5.2): AEAD-encrypt one message.
 *
 * Uses the per-context nonce derived from the base nonce and the current
 * sequence number, then increments the sequence number. Each call must be
 * matched by an mbedtls_hpke_open() call on the recipient context.
 *
 * \param ctx               A sender context produced by
 *                          mbedtls_hpke_setup_base_s().
 * \param aad               Additional authenticated data. May be \c NULL
 *                          if \p aad_len is 0.
 * \param aad_len           Length of \p aad in bytes.
 * \param plaintext         The message to encrypt. May be \c NULL if
 *                          \p plaintext_len is 0.
 * \param plaintext_len     Length of \p plaintext in bytes.
 * \param ciphertext        Output buffer receiving the ciphertext followed
 *                          by the 16-byte authentication tag.
 * \param ciphertext_size   Size of the \p ciphertext buffer.
 * \param ciphertext_len    On success, the number of bytes written, equal
 *                          to \p plaintext_len plus
 *                          #MBEDTLS_HPKE_TAG_LEN.
 *
 * \return                  \c 0 on success.
 * \return                  #MBEDTLS_ERR_HPKE_BAD_STATE if the context is
 *                          not a live sender context, including when the
 *                          sequence number limit has been reached
 *                          (mbedtls_hpke_message_limit() returns \c 1).
 * \return                  #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA on a bad
 *                          parameter.
 * \return                  #MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL if
 *                          \p ciphertext_size is smaller than
 *                          \p plaintext_len + #MBEDTLS_HPKE_TAG_LEN.
 * \return                  Another negative error code on cryptographic
 *                          failure.
 */
int mbedtls_hpke_seal(mbedtls_hpke_context *ctx,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *plaintext, size_t plaintext_len,
                      unsigned char *ciphertext, size_t ciphertext_size,
                      size_t *ciphertext_len);

/**
 * \brief HPKE Open (RFC 9180 section 5.2): AEAD-decrypt one message.
 *
 * Uses the per-context nonce derived from the base nonce and the current
 * sequence number, then increments the sequence number only on success.
 * On authentication failure nothing is written to \p plaintext and the
 * sequence number is not incremented, so the failure does not
 * desynchronize the context.
 *
 * \param ctx               A recipient context produced by
 *                          mbedtls_hpke_setup_base_r().
 * \param aad               Additional authenticated data. Must match the
 *                          \p aad used by the sender. May be \c NULL if
 *                          \p aad_len is 0.
 * \param aad_len           Length of \p aad in bytes.
 * \param ciphertext        The ciphertext including the trailing 16-byte
 *                          tag.
 * \param ciphertext_len    Length of \p ciphertext in bytes. Must be at
 *                          least #MBEDTLS_HPKE_TAG_LEN.
 * \param plaintext         Output buffer receiving the decrypted message.
 *                          It may alias \p ciphertext (in-place
 *                          decryption) only when the buffers start at the
 *                          same address; otherwise the buffers must not
 *                          overlap.
 * \param plaintext_size    Size of the \p plaintext buffer.
 * \param plaintext_len     On success, the number of bytes written, equal
 *                          to \p ciphertext_len minus
 *                          #MBEDTLS_HPKE_TAG_LEN.
 *
 * \return                  \c 0 on success.
 * \return                  #MBEDTLS_ERR_HPKE_AUTH_FAILED if the tag does
 *                          not verify; in this case \p plaintext is not
 *                          modified and no information about it is
 *                          leaked through the return value.
 * \return                  #MBEDTLS_ERR_HPKE_BAD_STATE if the context is
 *                          not a live recipient context, including when
 *                          the sequence number limit has been reached.
 * \return                  #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA on a bad
 *                          parameter or a ciphertext shorter than the tag.
 * \return                  #MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL if
 *                          \p plaintext_size is too small.
 * \return                  Another negative error code on cryptographic
 *                          failure.
 */
int mbedtls_hpke_open(mbedtls_hpke_context *ctx,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *ciphertext,
                      size_t ciphertext_len,
                      unsigned char *plaintext, size_t plaintext_size,
                      size_t *plaintext_len);

/**
 * \brief HPKE Export (RFC 9180 section 5.3).
 *
 * Derives a secret of up to #MBEDTLS_HPKE_MAX_EXPORT_LEN bytes bound to
 * \p exporter_context. Sender and recipient contexts derive identical
 * values when given the same arguments. Export does not consume sequence
 * numbers and does not affect later Seal/Open calls.
 *
 * \param ctx               A live sender or recipient context.
 * \param exporter_context  The exporter context string. May be \c NULL if
 *                          \p exporter_context_len is 0.
 * \param exporter_context_len  Length of \p exporter_context in bytes.
 * \param length            Number of bytes to export, at most
 *                          #MBEDTLS_HPKE_MAX_EXPORT_LEN.
 * \param exported          Output buffer of at least \p length bytes.
 *
 * \return                  \c 0 on success.
 * \return                  #MBEDTLS_ERR_HPKE_BAD_STATE if the context is
 *                          not live.
 * \return                  #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA on a bad
 *                          parameter, including an excessive \p length.
 * \return                  Another negative error code on cryptographic
 *                          failure.
 */
int mbedtls_hpke_export(mbedtls_hpke_context *ctx,
                        const unsigned char *exporter_context,
                        size_t exporter_context_len,
                        size_t length,
                        unsigned char *exported);

/**
 * \brief Report whether the context has exhausted its message sequence.
 *
 * RFC 9180 forbids sealing or opening once the sequence number would
 * overflow the nonce. The maximum safe number of messages is
 * 2^(8*Nn) - 1; with Nn = 12 this is 2^96 - 1, which cannot be reached
 * in practice, but the limit is enforced regardless.
 *
 * \param ctx   A live context.
 *
 * \return      \c 1 if no further Seal/Open call is permitted, otherwise
 *              \c 0. Also returns \c 1 for an uninitialized or freed
 *              context.
 */
int mbedtls_hpke_message_limit(const mbedtls_hpke_context *ctx);

/**
 * \brief Clear and release an HPKE context.
 *
 * Zeroizes all key material, sequence state and metadata held in the
 * context. After this call the context is back to the initialized state
 * and may be set up again. Calling this on an already-initialized
 * context is safe.
 *
 * \param ctx   The context to clear. May be \c NULL, in which case this
 *              call does nothing.
 */
void mbedtls_hpke_free(mbedtls_hpke_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HPKE_C */

#endif /* MBEDTLS_HPKE_H */
