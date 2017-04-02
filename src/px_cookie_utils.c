#include "px_cookie_utils.h"

#include <apr_pools.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;
static const int HASH_LEN = 65;

const char *SEPERATOR = ":";

/**
 * parse raw px_cookie to cookie_parts.
 * return the size of cookie parts, -1 on failure
 **/
// TODO: cookei parts should be allocated here!
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

const char *decode_cookie(const char *px_cookie, const char *cookie_key, apr_pool_t *pool) {
    char *px_cookie_cpy = apr_pstrdup(pool, px_cookie);
    // parse cookie
    /*char *saveptr;*/
    /*const char *encoded_salt = strtok_r(px_cookie_cpy, SEPERATOR, &saveptr);*/
    /*parse_cookie();*/
    const char *encoded_salt, *iterations_str, *encoded_payload, *hash;
    //TODO: change this to map
    if (cookie_parts_size == 4) {
        hash = cookie_parts[0];
        encoded_salt = cookie_parts[1];
        iterations_str = cookie_parts[2];
        encoded_payload = cookie_parts[3];
    } else if (cookie_parts_size == 3) {
        hash = NULL;
        encoded_salt = cookie_parts[0];
        iterations_str = cookie_parts[1];
        encoded_payload = cookie_parts[2];
    }
    /*else {*/
        /*return NULL;*/
    /*}*/
    if (encoded_salt == NULL) {
        /*INFO(r_ctx->r->server, "Stoping cookie decryption: no valid salt in cookie");*/
        return NULL;
    }
    /*const char* iterations_str = strtok_r(NULL, SEPERATOR, &saveptr);*/
    if (iterations_str == NULL) {
        /*INFO(r_ctx->r->server, "Stoping cookie decryption: no valid iterations in cookie");*/
        return NULL;
    }
    apr_int64_t iterations = apr_atoi64(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        /*ERROR(r_ctx->r->server,"Number of iterations is illegal - %"APR_INT64_T_FMT , iterations);*/
        return NULL;
    }
    /*const char* encoded_payload = strtok_r(NULL, SEPERATOR, &saveptr);*/
    if (encoded_payload == NULL) {
        /*INFO(r_ctx->r->server,"Stoping cookie decryption: no valid encoded_payload in cookie");*/
        return NULL;
    }

    // decode payload
    unsigned char *payload;
    int payload_len;
    decode_base64(encoded_payload, &payload, &payload_len, pool);

    // decode salt
    unsigned char *salt;
    int salt_len;
    decode_base64(encoded_salt, &salt, &salt_len, pool);

    // pbkdf2
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(pool, IV_LEN + KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(cookie_key, strlen(cookie_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + KEY_LEN, pbdk2_out) == 0) {
        /*ERROR(r_ctx->r->server,"PKCS5_PBKDF2_HMAC_SHA256 failed");*/
        return NULL;
    }
    const unsigned char key[KEY_LEN];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[IV_LEN];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        /*ERROR(r_ctx->r->server, "Decryption failed in: Init");*/
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        /*ERROR(r_ctx->r->server, "Decryption failed in: Update");*/
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        /*ERROR(r_ctx->r->server, "Decryption failed in: Final");*/
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse cookie string to risk struct
    // parse the cookie from string in a different place
    // risk_cookie *c = parse_risk_cookie((const char*)dpayload, r_ctx); // take the parse from here
    /*r_ctx->px_cookie_decrypted = dpayload;*/ //TODO: don't forget to attach this

    // clean memory
    EVP_CIPHER_CTX_free(ctx);
    return dpayload;
}
