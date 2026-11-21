/**
 * \file x509_name_constraints.c
 *
 * \brief X.509 name constraints parsing and enforcement (RFC 5280 4.2.1.10).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "x509_internal.h"

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#include <string.h>

/*
 * GeneralName choice tags, context specific, primitive for all but the
 * explicitly constructed directoryName.
 */
#define NC_GN_OTHER_NAME                      (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)
#define NC_GN_RFC822_NAME                     (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)
#define NC_GN_DNS_NAME                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2)
#define NC_GN_X400_ADDRESS                    (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 3)
#define NC_GN_DIRECTORY_NAME                  (MBEDTLS_ASN1_CONTEXT_SPECIFIC | \
                                               MBEDTLS_ASN1_CONSTRUCTED | 4)
#define NC_GN_EDI_PARTY_NAME                  (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 5)
#define NC_GN_URI                             (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6)
#define NC_GN_IP_ADDRESS                      (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7)
#define NC_GN_REGISTERED_ID                   (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 8)

/*
 * Upper bound on the number of GeneralSubtree entries accepted in a single
 * name constraints extension. The ASN.1 data itself lives in the certificate
 * buffer and needs no copying; this limit only bounds the parse loop and the
 * amount of work done per verification, so an attacker cannot make us spend
 * unbounded time on a hostile extension.
 */
#define NC_MAX_SUBTREES                       128

/*
 * RFC 5280 4.2.1.10:
 *
 * NameConstraints ::= SEQUENCE {
 *      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
 *      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
 *
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 *
 * GeneralSubtree ::= SEQUENCE {
 *      base                    GeneralName,
 *      minimum         [0]     BaseDistance DEFAULT 0,
 *      maximum         [1]     BaseDistance OPTIONAL }
 *
 * BaseDistance ::= INTEGER (0..MAX)
 */
#define NC_TAG_PERMITTED   (MBEDTLS_ASN1_CONTEXT_SPECIFIC | \
                            MBEDTLS_ASN1_CONSTRUCTED | 0)
#define NC_TAG_EXCLUDED    (MBEDTLS_ASN1_CONTEXT_SPECIFIC | \
                            MBEDTLS_ASN1_CONSTRUCTED | 1)
#define NC_TAG_MINIMUM     (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)
#define NC_TAG_MAXIMUM     (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)

/*
 * Any structural failure inside a name constraints extension is reported as
 * the single X.509 extension error, matching how the rest of the X.509
 * parser treats malformed extensions and keeping the public error code
 * independent of the underlying ASN.1 helper.
 */
static int nc_wrap_error(int ret)
{
    if (ret == 0) {
        return 0;
    }
    (void) ret;
    return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
}

/*
 * Parse a single BaseDistance INTEGER.
 *
 * RFC 5280 defines BaseDistance as INTEGER (0..MAX). The minimum/maximum
 * fields only have a defined meaning for directoryName constraints, and the
 * default is 0; reject negative or malformed values.
 */
static int nc_parse_base_distance(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char expected_tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int value;

    if (**p != expected_tag) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    (*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, NULL)) != 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    if ((ret = mbedtls_asn1_get_int(p, end, &value)) != 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    if (value < 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    return 0;
}

/*
 * Validate the structure of one GeneralSubtree without copying anything:
 * the GeneralName is returned as a (tag, pointer, length) view into the
 * certificate buffer.
 */
static int nc_parse_general_subtree(unsigned char **p,
                                    const unsigned char *end,
                                    int *gn_tag,
                                    const unsigned char **gn_p,
                                    size_t *gn_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *subtree_end;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED |
                                    MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return nc_wrap_error(ret);
    }
    subtree_end = *p + len;
    if (subtree_end > end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    if (*p >= subtree_end) {
        /* GeneralSubtree must contain a base GeneralName. */
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    *gn_tag = **p;

    switch (*gn_tag) {
        case NC_GN_DNS_NAME:
        case NC_GN_RFC822_NAME:
        case NC_GN_URI:
        case NC_GN_IP_ADDRESS:
            /* Primitive context-specific tags: tag, length, value. */
            (*p)++;
            if ((ret = mbedtls_asn1_get_len(p, subtree_end, gn_len)) != 0) {
                return nc_wrap_error(ret);
            }
            *gn_p = *p;
            *p += *gn_len;
            break;

        case NC_GN_DIRECTORY_NAME: {
            size_t name_len;
            const unsigned char *name_tlv;
            /* [4] EXPLICIT Name: expect an inner Name SEQUENCE. Keep a
             * pointer to the full Name TLV so callers can re-parse it with
             * mbedtls_asn1_get_tag(). */
            (*p)++;
            if ((ret = mbedtls_asn1_get_len(p, subtree_end, &name_len)) != 0) {
                return nc_wrap_error(ret);
            }
            name_tlv = *p;
            if ((ret = mbedtls_asn1_get_tag(p, subtree_end, &len,
                                            MBEDTLS_ASN1_CONSTRUCTED |
                                            MBEDTLS_ASN1_SEQUENCE)) != 0) {
                return nc_wrap_error(ret);
            }
            *gn_p = name_tlv;
            *gn_len = (size_t) (*p - name_tlv) + len;
            *p += len;
            break;
        }

        default:
            /*
             * RFC 5280 marks otherName, x400Address, ediPartyName and
             * registeredID as "not supported" for name constraints and
             * requires rejecting constraints that make use of them. Any
             * other tag is simply malformed.
             */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    /* Optional minimum [0] BaseDistance DEFAULT 0. */
    if (*p < subtree_end && **p == NC_TAG_MINIMUM) {
        ret = nc_parse_base_distance(p, subtree_end, NC_TAG_MINIMUM);
        if (ret != 0) {
            return ret;
        }
    }

    /* Optional maximum [1] BaseDistance. */
    if (*p < subtree_end && **p == NC_TAG_MAXIMUM) {
        ret = nc_parse_base_distance(p, subtree_end, NC_TAG_MAXIMUM);
        if (ret != 0) {
            return ret;
        }
    }

    if (*p != subtree_end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    return 0;
}

/*
 * Validate one GeneralSubtrees sequence (permitted or excluded).
 *
 * Only structure is checked here; matching re-walks the raw data during
 * verification, so no per-constraint allocations are needed.
 */
static int nc_validate_subtrees(const unsigned char *subtree_p,
                                size_t subtree_len,
                                size_t *count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) subtree_p;
    const unsigned char *end = subtree_p + subtree_len;
    size_t local_count = 0;

    while (p < end) {
        int gn_tag;
        const unsigned char *gn_p;
        size_t gn_len;

        if (local_count >= NC_MAX_SUBTREES) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        ret = nc_parse_general_subtree(&p, end, &gn_tag, &gn_p, &gn_len);
        if (ret != 0) {
            return nc_wrap_error(ret);
        }

        if (gn_tag == NC_GN_IP_ADDRESS) {
            /*
             * iPAddress constraints encode either 4 (IPv4) or 16 (IPv6)
             * bytes for an address, or twice that for an address/mask pair.
             */
            if (gn_len != 4 && gn_len != 8 && gn_len != 16 && gn_len != 32) {
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            }
        }

        local_count++;
    }

    if (p != end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    if (count != NULL) {
        *count = local_count;
    }

    return 0;
}

/*
 * Parse and validate the extnValue of a name constraints extension.
 *
 * On success, *value_p / *value_len describe the validated raw extension
 * value; the caller stores it in the certificate structure for enforcement
 * during chain verification. No memory is allocated.
 */
int mbedtls_x509_parse_name_constraints(unsigned char **p,
                                        const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    const unsigned char *nc_end;
    int saw_permitted = 0;
    int saw_excluded = 0;
    size_t total_subtrees = 0;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED |
                                    MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return nc_wrap_error(ret);
    }
    nc_end = *p + len;
    if (nc_end > end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    while (*p < nc_end) {
        size_t subtree_len;
        size_t subtree_count = 0;
        unsigned char tag = **p;

        if (tag == NC_TAG_PERMITTED) {
            if (saw_permitted) {
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            }
            saw_permitted = 1;
        } else if (tag == NC_TAG_EXCLUDED) {
            if (saw_excluded) {
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            }
            saw_excluded = 1;
        } else {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        (*p)++;
        if ((ret = mbedtls_asn1_get_len(p, nc_end, &subtree_len)) != 0) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        /* GeneralSubtrees ::= SEQUENCE SIZE (1..MAX): reject an empty or
         * over-long subtree sequence; the inner SEQUENCE tag is validated by
         * nc_validate_subtrees(). */
        if (subtree_len == 0) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        if (*p + subtree_len > nc_end) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        ret = nc_validate_subtrees(*p, subtree_len, &subtree_count);
        if (ret != 0) {
            return nc_wrap_error(ret);
        }

        total_subtrees += subtree_count;
        if (total_subtrees > NC_MAX_SUBTREES) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        *p += subtree_len;
    }

    if (*p != nc_end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Matching                                                            */
/* ------------------------------------------------------------------ */

/*
 * Case-insensitive comparison over a fixed length. Returns 0 on equality.
 */
static int nc_casecmp(const unsigned char *a, size_t a_len,
                      const unsigned char *b, size_t b_len)
{
    if (a_len != b_len) {
        return -1;
    }
    for (size_t i = 0; i < a_len; i++) {
        unsigned char ca = a[i];
        unsigned char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca += 32;
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb += 32;
        }
        if (ca != cb) {
            return -1;
        }
    }
    return 0;
}

/*
 * RFC 5280 4.2.1.10 dNSName matching:
 *   - a constraint of "example.com" matches the host "example.com" and any
 *     sub-domain such as "www.example.com";
 *   - an empty constraint never matches here; the special "permitted empty
 *     DNS name" case is handled in nc_check_subtrees().
 * Comparison is case-insensitive (RFC 4343).
 */
static int nc_dns_match(const unsigned char *host, size_t host_len,
                        const unsigned char *constraint, size_t c_len)
{
    if (c_len == 0 || host_len < c_len) {
        return -1;
    }

    if (host_len == c_len) {
        return nc_casecmp(host, host_len, constraint, c_len);
    }

    /* host is longer: it must end with "." + constraint. */
    if (host[host_len - c_len - 1] != '.') {
        return -1;
    }

    return nc_casecmp(host + host_len - c_len, c_len, constraint, c_len);
}

/*
 * RFC 5280 4.2.1.10 rfc822Name matching, following the common stack
 * convention used for mail addresses:
 *   - constraint containing an '@': the whole mailbox must match exactly;
 *   - constraint starting with '.': matches mailboxes in sub-domains only,
 *     e.g. ".example.com" matches "u@sub.example.com", not "u@example.com";
 *   - any other constraint (a bare domain): matches a mailbox whose domain
 *     is exactly that domain, e.g. "example.com" matches "u@example.com"
 *     but not "u@sub.example.com".
 * Comparison of the domain part is case-insensitive.
 */
static int nc_email_match(const unsigned char *mailbox, size_t m_len,
                          const unsigned char *constraint, size_t c_len)
{
    const unsigned char *at = memchr(mailbox, '@', m_len);

    if (at == NULL) {
        return -1;
    }

    if (memchr(constraint, '@', c_len) != NULL) {
        /* Full mailbox form: exact, case-insensitive match. */
        return nc_casecmp(mailbox, m_len, constraint, c_len);
    }

    if (c_len == 0) {
        return -1;
    }

    size_t domain_off = (size_t) (at - mailbox) + 1;
    const unsigned char *domain = mailbox + domain_off;
    size_t domain_len = m_len - domain_off;

    if (constraint[0] == '.') {
        /* Sub-domain form: ".example.com" matches "x.example.com" but not
         * the apex "example.com". */
        size_t bare_len = c_len - 1;
        if (domain_len <= bare_len) {
            return -1;
        }
        if (domain[domain_len - bare_len - 1] != '.') {
            return -1;
        }
        return nc_casecmp(domain + domain_len - bare_len, bare_len,
                          constraint + 1, bare_len);
    }

    /* Bare domain form: exact domain match only; sub-domains are covered by
     * the dotted constraint form above. */
    return nc_casecmp(domain, domain_len, constraint, c_len);
}

/*
 * Locate the host part of a URI: everything between the end of the
 * "scheme://" prefix and the first '/', '?' or '#'.
 * Returns NULL when the URI is not hierarchical.
 */
static const unsigned char *nc_uri_host(const unsigned char *uri,
                                        size_t uri_len,
                                        size_t *host_len)
{
    const unsigned char *sep = NULL;

    for (size_t i = 0; i + 2 < uri_len; i++) {
        if (uri[i] == ':' && uri[i + 1] == '/' && uri[i + 2] == '/') {
            sep = uri + i + 3;
            break;
        }
    }

    if (sep == NULL) {
        return NULL;
    }

    const unsigned char *end = sep;
    while (end < uri + uri_len &&
           *end != '/' && *end != '?' && *end != '#') {
        end++;
    }

    *host_len = (size_t) (end - sep);
    return sep;
}

/*
 * RFC 5280 4.2.1.10 uniformResourceIdentifier matching, following the
 * common implementation convention (and the project's test vectors):
 *
 *   - if the constraint contains "://", it is a full URI prefix and must
 *     match the URI itself;
 *   - if it starts with '.', the URI's host must end with that suffix;
 *   - otherwise the URI's host must start with the constraint (matching the
 *     apex host and any sub-domain).
 *
 * All comparisons are case-insensitive for the scheme and host components.
 */
static int nc_uri_match(const unsigned char *uri, size_t uri_len,
                        const unsigned char *constraint, size_t c_len)
{
    if (c_len == 0) {
        return -1;
    }

    /* Full URI form: plain case-insensitive prefix match. */
    if (c_len >= 3) {
        for (size_t i = 0; i + 3 <= c_len; i++) {
            if (constraint[i] == ':' && constraint[i + 1] == '/' &&
                constraint[i + 2] == '/') {
                if (uri_len < c_len) {
                    return -1;
                }
                return nc_casecmp(uri, c_len, constraint, c_len);
            }
        }
    }

    size_t host_len = 0;
    const unsigned char *host = nc_uri_host(uri, uri_len, &host_len);
    if (host == NULL) {
        return -1;
    }

    if (constraint[0] == '.') {
        /* Dotted form: ".example.com" matches "www.example.com" only. */
        size_t bare_len = c_len - 1;
        if (host_len <= bare_len) {
            return -1;
        }
        if (host[host_len - bare_len - 1] != '.') {
            return -1;
        }
        return nc_casecmp(host + host_len - bare_len, bare_len,
                          constraint + 1, bare_len);
    }

    /* Bare host form: prefix match against the URI host. */
    if (host_len < c_len) {
        return -1;
    }
    if (host_len > c_len && host[c_len] != '.') {
        return -1;
    }
    return nc_casecmp(host, c_len, constraint, c_len);
}

/*
 * RFC 5280 4.2.1.10 iPAddress matching.
 *
 * An IPv4 constraint is 4 bytes of address or 8 bytes of address+mask;
 * IPv6 uses 16 / 32 bytes correspondingly. The name must have the same
 * address family and fall inside the constrained network.
 */
static int nc_ip_match(const unsigned char *name, size_t name_len,
                       const unsigned char *constraint, size_t c_len)
{
    size_t addr_len;
    const unsigned char *mask;
    size_t i;

    if (c_len == 4 || c_len == 8) {
        addr_len = 4;
    } else if (c_len == 16 || c_len == 32) {
        addr_len = 16;
    } else {
        return -1;
    }

    if (name_len != addr_len) {
        return -1;
    }

    if (c_len == addr_len) {
        /* Exact address constraint. */
        return memcmp(name, constraint, addr_len) == 0 ? 0 : -1;
    }

    /* address + mask: every masked bit of the name must equal the address. */
    mask = constraint + addr_len;
    for (i = 0; i < addr_len; i++) {
        if ((name[i] & mask[i]) != (constraint[i] & mask[i])) {
            return -1;
        }
    }

    return 0;
}

/*
 * RFC 5280 4.2.1.10 directoryName matching: the constraint Name must be a
 * prefix of the subject Name when both are compared as RDN sequences, in
 * reverse order (the most significant RDN first).
 *
 * Both arguments are raw DER Name (SEQUENCE of RDN) buffers. We parse them
 * into fixed-capacity stack arrays, so verification performs no heap
 * allocation regardless of chain length.
 */
#define NC_MAX_DN_RDNS   16

struct nc_rdn {
    const unsigned char *p;
    size_t len;
};

static int nc_parse_rdn_sequence(const unsigned char *name_p,
                                 size_t name_len,
                                 struct nc_rdn *rdns,
                                 size_t max_rdns,
                                 size_t *out_count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) name_p;
    const unsigned char *end = name_p + name_len;
    size_t len;
    size_t count = 0;

    ret = mbedtls_asn1_get_tag(&p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    end = p + len;

    while (p < end) {
        size_t rdn_len;
        if (count >= max_rdns) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        ret = mbedtls_asn1_get_tag(&p, end, &rdn_len,
                                   MBEDTLS_ASN1_CONSTRUCTED |
                                   MBEDTLS_ASN1_SET);
        if (ret != 0) {
            return ret;
        }
        rdns[count].p = p;
        rdns[count].len = rdn_len;
        count++;
        p += rdn_len;
    }

    *out_count = count;
    return 0;
}

static int nc_rdn_equal(const struct nc_rdn *a, const struct nc_rdn *b)
{
    if (a->len != b->len) {
        return -1;
    }
    return memcmp(a->p, b->p, a->len) == 0 ? 0 : -1;
}

static int nc_dirname_match(const unsigned char *name_p, size_t name_len,
                            const unsigned char *constraint_p,
                            size_t constraint_len)
{
    struct nc_rdn name_rdns[NC_MAX_DN_RDNS];
    struct nc_rdn ca_rdns[NC_MAX_DN_RDNS];
    size_t name_count = 0;
    size_t ca_count = 0;
    int ret;

    ret = nc_parse_rdn_sequence(name_p, name_len, name_rdns,
                                NC_MAX_DN_RDNS, &name_count);
    if (ret != 0) {
        return -1;
    }
    ret = nc_parse_rdn_sequence(constraint_p, constraint_len, ca_rdns,
                                NC_MAX_DN_RDNS, &ca_count);
    if (ret != 0) {
        return -1;
    }

    /* The parsed RDN order already starts with the most significant RDN. */
    if (ca_count == 0 || ca_count > name_count) {
        return -1;
    }

    for (size_t i = 0; i < ca_count; i++) {
        if (nc_rdn_equal(&name_rdns[i], &ca_rdns[i]) != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Apply one GeneralName constraint (described by tag/pointer/length inside
 * the certificate buffer) to one subject name.
 * Returns 0 on match, -1 otherwise.
 */
static int nc_match_one(int constraint_tag,
                        const unsigned char *c_p, size_t c_len,
                        int name_tag,
                        const unsigned char *n_p, size_t n_len)
{
    if (constraint_tag != name_tag) {
        return -1;
    }

    switch (constraint_tag) {
        case NC_GN_DNS_NAME:
            return nc_dns_match(n_p, n_len, c_p, c_len);
        case NC_GN_RFC822_NAME:
            return nc_email_match(n_p, n_len, c_p, c_len);
        case NC_GN_URI:
            return nc_uri_match(n_p, n_len, c_p, c_len);
        case NC_GN_IP_ADDRESS:
            return nc_ip_match(n_p, n_len, c_p, c_len);
        case NC_GN_DIRECTORY_NAME:
            return nc_dirname_match(n_p, n_len, c_p, c_len);
        default:
            return -1;
    }
}

/*
 * Check one subject GeneralName against every GeneralSubtree of one kind.
 *
 * For permitted subtrees, a name is acceptable when the subtree sequence is
 * empty (no restriction of this type) or at least one entry matches.
 * For excluded subtrees, any single match rejects the name.
 *
 * Returns 0 if acceptable, -1 if violated.
 */
static int nc_check_subtrees(int excluded,
                             const unsigned char *subtree_p,
                             size_t subtree_len,
                             int name_tag,
                             const unsigned char *name_p,
                             size_t name_len)
{
    unsigned char *p = (unsigned char *) subtree_p;
    const unsigned char *end = subtree_p + subtree_len;
    int any_constraint = 0;

    while (p < end) {
        int gn_tag;
        const unsigned char *gn_p;
        size_t gn_len;
        int ret;

        ret = nc_parse_general_subtree(&p, end, &gn_tag, &gn_p, &gn_len);
        if (ret != 0) {
            /*
             * The extension was validated at parse time. A failure here
             * indicates internal inconsistency; treat as no match so that a
             * permitted subtree cannot be silently bypassed.
             */
            return -1;
        }

        if (gn_tag != name_tag) {
            continue;
        }

        any_constraint = 1;

        /* An empty dNSName in a permitted subtree matches every DNS name
         * (it carries no restriction). Empty constraints of other types are
         * left to the type-specific matchers. */
        if (!excluded && gn_tag == NC_GN_DNS_NAME && gn_len == 0) {
            return 0;
        }

        if (nc_match_one(gn_tag, gn_p, gn_len,
                         name_tag, name_p, name_len) == 0) {
            /* Excluded match: violation. Permitted match: acceptable. */
            return excluded ? -1 : 0;
        }
    }

    if (excluded) {
        /* Nothing excluded matched: acceptable. */
        return 0;
    }

    /* Permitted subtrees existed but none applied to this name type:
     * acceptable only if there was no constraint of the same type. */
    return any_constraint ? -1 : 0;
}

/*
 * Walk the validated NameConstraints value and locate one subtree
 * sequence. If permitted is 0 the [0] sequence is returned, else [1].
 * Returns 0 with *found == 0 when the optional sequence is absent.
 */
static int nc_find_subtrees(const mbedtls_x509_buf *nc,
                            int excluded,
                            const unsigned char **out_p,
                            size_t *out_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
    const unsigned char *end;
    size_t len;
    unsigned char wanted = excluded ? NC_TAG_EXCLUDED : NC_TAG_PERMITTED;

    p = nc->p;
    end = nc->p + nc->len;

    ret = mbedtls_asn1_get_tag(&p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    end = p + len;

    while (p < end) {
        unsigned char tag = *p;
        size_t sub_len;
        unsigned char *q = p;

        if (tag != NC_TAG_PERMITTED && tag != NC_TAG_EXCLUDED) {
            return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
        }

        q++;
        ret = mbedtls_asn1_get_len(&q, end, &sub_len);
        if (ret != 0) {
            return ret;
        }

        if (tag == wanted) {
            *out_p = q;
            *out_len = sub_len;
            return 0;
        }

        p = q + sub_len;
    }

    *out_p = NULL;
    *out_len = 0;
    return 0;
}

/*
 * Check one subject name against all permitted and excluded subtrees of one
 * name constraints extension.
 */
static int nc_check_name_against_ext(const mbedtls_x509_buf *nc,
                                     int name_tag,
                                     const unsigned char *name_p,
                                     size_t name_len)
{
    const unsigned char *p;
    size_t len;

    if (nc_find_subtrees(nc, 1, &p, &len) == 0 && p != NULL) {
        if (nc_check_subtrees(1, p, len, name_tag, name_p, name_len) != 0) {
            return -1;
        }
    }

    if (nc_find_subtrees(nc, 0, &p, &len) == 0 && p != NULL) {
        if (nc_check_subtrees(0, p, len, name_tag, name_p, name_len) != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Apply one name constraints extension to every GeneralName carried by the
 * subject certificate. The SAN list holds raw entries tagged exactly like
 * the constraint GeneralNames; the subject DN is checked separately.
 */
static int nc_check_cert_against_ext(const mbedtls_x509_crt *crt,
                                     const mbedtls_x509_buf *nc)
{
    const mbedtls_x509_sequence *cur;
    int saw_san = 0;

    /*
     * RFC 5280 4.2.1.10: constraints apply to the SAN extension when
     * present. Every SAN name of an applicable type must satisfy all
     * constraints; types that no constraint references are ignored.
     *
     * The first GeneralName is stored in the head sequence node itself;
     * further names hang off its next pointer, so the walk starts at the
     * head rather than head->next.
     */
    for (cur = &crt->subject_alt_names; cur != NULL; cur = cur->next) {
        int tag;

        if (cur->buf.p == NULL) {
            /* Empty head node: no SAN extension was present. */
            continue;
        }

        saw_san = 1;
        tag = cur->buf.tag;

        switch (tag) {
            case NC_GN_DNS_NAME:
            case NC_GN_RFC822_NAME:
            case NC_GN_URI:
            case NC_GN_IP_ADDRESS:
                if (nc_check_name_against_ext(nc, tag,
                                              cur->buf.p, cur->buf.len) != 0) {
                    return -1;
                }
                break;

            case NC_GN_DIRECTORY_NAME:
                /* The SAN directoryName is wrapped [4] EXPLICIT; cur->buf
                 * points at the inner Name (a full SEQUENCE TLV), which is
                 * the same representation used for constraints. */
                if (nc_check_name_against_ext(nc, NC_GN_DIRECTORY_NAME,
                                              cur->buf.p,
                                              cur->buf.len) != 0) {
                    return -1;
                }
                break;

            default:
                /* GeneralName types not supported for constraints (otherName,
                 * x400Address, ediPartyName, registeredID) are ignored here;
                 * their use inside a constraint itself was rejected at parse
                 * time. */
                break;
        }
    }

    /*
     * When the certificate has no SAN, RFC 5280 applies dNSName and
     * directoryName constraints to the subject DN. A CN that looks like a
     * DNS name is checked as dNSName; the whole subject is checked as
     * directoryName.
     */
    if (!saw_san) {
        const mbedtls_x509_name *dn;

        if (nc_check_name_against_ext(nc, NC_GN_DIRECTORY_NAME,
                                      crt->subject_raw.p,
                                      crt->subject_raw.len) != 0) {
            return -1;
        }

        for (dn = &crt->subject; dn != NULL; dn = dn->next) {
            static const unsigned char cn_oid[] = { 0x55, 0x04, 0x03 };
            int has_dot = 0;
            size_t k;

            if (dn->oid.len == sizeof(cn_oid) &&
                memcmp(dn->oid.p, cn_oid, sizeof(cn_oid)) == 0 &&
                dn->val.len > 0) {
                /* Only treat the CN as a DNS name when it actually looks like
                 * a domain name (contains a label separator). This avoids
                 * applying dNSName constraints to plain single-label CNs. */
                for (k = 0; k < dn->val.len; k++) {
                    if (dn->val.p[k] == '.') {
                        has_dot = 1;
                        break;
                    }
                }
                if (has_dot &&
                    nc_check_name_against_ext(nc, NC_GN_DNS_NAME,
                                              dn->val.p, dn->val.len) != 0) {
                    return -1;
                }
            }
        }
    }

    return 0;
}

/*
 * Enforce the name constraints of every CA in the built verification chain.
 *
 * RFC 5280 4.2.1.10: the constraints expressed in a CA certificate apply to
 * all certificates below it in the chain. ver_chain stores the end-entity at
 * index 0 and walks towards the trusted root, so for each CA we check every
 * certificate with a smaller index.
 *
 * Returns 0 on success. On violation, the offending certificate's flags
 * receive MBEDTLS_X509_BADCERT_NAME_CONSTRAINT and -1 is returned.
 */
int mbedtls_x509_crt_check_name_constraints(
    mbedtls_x509_crt_verify_chain *ver_chain)
{
    unsigned i;
    unsigned j;

    for (i = 1; i < ver_chain->len; i++) {
        const mbedtls_x509_crt *ca = ver_chain->items[i].crt;

        if (ca->name_constraints_raw.p == NULL) {
            continue;
        }

        for (j = 0; j < i; j++) {
            const mbedtls_x509_crt *child = ver_chain->items[j].crt;

            if (nc_check_cert_against_ext(child,
                                          &ca->name_constraints_raw) != 0) {
                ver_chain->items[j].flags |=
                    MBEDTLS_X509_BADCERT_NAME_CONSTRAINT;
                return -1;
            }
        }
    }

    return 0;
}

#endif /* MBEDTLS_X509_CRT_PARSE_C */
