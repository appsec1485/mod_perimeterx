#include "px_cookie_utils.h"

#include <apr_pools.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

const char *SEPERATOR = ":";

/**
 * parse raw px_cookie to cookie_parts.
 * return the size of cookie parts, -1 on failure
 **/
int parse_cookie(char *px_cookie, char **cookie_parts) {
    if (px_cookie == NULL) return -1;
    if (cookie_parts == NULL) return -1;

    char *last;
    cookie_parts[0] = apr_strtok(px_cookie, SEPERATOR, &last);
    if (cookie_parts[0] == NULL) {
        return 0;
    }
    cookie_parts[1] = apr_strtok(NULL, SEPERATOR, &last);
    if (cookie_parts[1] == NULL) {
        return 1;
    }
    cookie_parts[2] = apr_strtok(NULL, SEPERATOR, &last);
    if (cookie_parts[1] == NULL) {
        return 2;
    }
    cookie_parts[3] = apr_strtok(NULL, SEPERATOR, &last);
    if (cookie_parts[3] == NULL) {
        return 3;
    }
    return 4;
}

/**
 *
 **/
int decode_base64(const char *s, unsigned char **o, int *len, apr_pool_t *p) {
    if (!s) {
        return -1;
    }
    int l = strlen(s);
    *o = (unsigned char*)apr_palloc(p, (l * 3 + 1));
    BIO *bio = BIO_new_mem_buf((void*)s, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, *o, l);
    BIO_free_all(b64);
    return 0;
}

/**
 *
 **/
void digest_cookie(const char *cookie_key, const char **signing_fields, int sign_fields_size, char *buffer, int buffer_len) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);

    HMAC_Init_ex(&hmac, cookie_key, strlen(cookie_key), EVP_sha256(), NULL);

    for (int i = 0; i < sign_fields_size; i++) {
        if (signing_fields[i]) {
            HMAC_Update(&hmac, signing_fields[i], strlen(signing_fields[i]));
        }
    }

    int len = buffer_len / 2;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    for (int i = 0; i < len; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}
