#include "px_cookie.h"
#include "px_cookie_utils.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <jansson.h>

#include <apr_tables.h>
#include <apr_strings.h>
#include <http_log.h>

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

static const int ITERATIONS_UPPER_BOUND = 10000;
static const int ITERATIONS_LOWER_BOUND = 0;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;
static const int HASH_LEN = 65;

risk_cookie *parse_risk_cookie(const char *raw_cookie, request_context *ctx) {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        ERROR(ctx->r->server, "cookie data: parse failed with error. raw_cookie (%s), text (%s)", raw_cookie, error.text);
        return NULL;
    }

    int a_val, b_val;
    char *hash, *uuid, *vid;
    json_int_t ts;
    if (json_unpack(j_cookie, "{s:s,s:s,s:{s:i,s:i},s:I,s:s}",
                "v", &vid,
                "u", &uuid,
                "s",
                "a", &a_val,
                "b", &b_val,
                "t", &ts,
                "h", &hash)) {
        ERROR(ctx->r->server, "cookie data: unpack json failed. raw_cookie (%s)", raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    risk_cookie *cookie = (risk_cookie*)apr_palloc(ctx->r->pool, sizeof(risk_cookie));
    if (!cookie) {
        ERROR(ctx->r->server, "cookie data: failed to allocate risk cookie struct. raw_cookie (%s)", raw_cookie);
        json_decref(j_cookie);
        return NULL;
    }

    char buf[30] = {0};
    snprintf(buf, sizeof(buf), "%"JSON_INTEGER_FORMAT, ts);
    cookie->timestamp = apr_pstrdup(ctx->r->pool, buf);
    cookie->ts = ts;
    cookie->hash = apr_pstrdup(ctx->r->pool, hash);
    cookie->uuid = apr_pstrdup(ctx->r->pool, uuid);
    cookie->vid = apr_pstrdup(ctx->r->pool, vid);
    cookie->a_val = a_val;
    cookie->b_val = b_val;
    cookie->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    cookie->b = apr_psprintf(ctx->r->pool, "%d", b_val);

    INFO(ctx->r->server,"cookie data: timestamp %s, vid %s, uuid %s hash %s scores: a %s b %s", cookie->timestamp, cookie->vid, cookie->uuid, cookie->hash, cookie->a, cookie->b);
    json_decref(j_cookie);
    return cookie;
}

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx) {
    char *px_cookie_cpy = apr_pstrdup(r_ctx->r->pool, px_cookie);
    // parse cookie
    char *saveptr;
    const char *delimieter = ":";
    const char *encoded_salt = strtok_r(px_cookie_cpy, delimieter, &saveptr);
    if (encoded_salt == NULL) {
        INFO(r_ctx->r->server, "Stoping cookie decryption: no valid salt in cookie");
        return NULL;
    }
    const char* iterations_str = strtok_r(NULL, delimieter, &saveptr);
    if (iterations_str == NULL) {
        INFO(r_ctx->r->server, "Stoping cookie decryption: no valid iterations in cookie");
        return NULL;
    }
    apr_int64_t iterations = apr_atoi64(iterations_str);
    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ERROR(r_ctx->r->server,"Number of iterations is illegal - %"APR_INT64_T_FMT , iterations);
        return NULL;
    }
    const char* encoded_payload = strtok_r(NULL, delimieter, &saveptr);
    if (encoded_payload == NULL) {
        INFO(r_ctx->r->server,"Stoping cookie decryption: no valid encoded_payload in cookie");
        return NULL;
    }

    // decode payload
    unsigned char *payload;
    int payload_len;
    decode_base64(encoded_payload, &payload, &payload_len, r_ctx->r->pool);

    // decode salt
    unsigned char *salt;
    int salt_len;
    decode_base64(encoded_salt, &salt, &salt_len, r_ctx->r->pool);

    // pbkdf2
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, IV_LEN + KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(cookie_key, strlen(cookie_key), salt, salt_len, iterations, EVP_sha256(),  IV_LEN + KEY_LEN, pbdk2_out) == 0) {
        ERROR(r_ctx->r->server,"PKCS5_PBKDF2_HMAC_SHA256 failed");
        return NULL;
    }
    const unsigned char key[KEY_LEN];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[IV_LEN];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Init");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(r_ctx->r->pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Update");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        ERROR(r_ctx->r->server, "Decryption failed in: Final");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse cookie string to risk struct
    risk_cookie *c = parse_risk_cookie((const char*)dpayload, r_ctx);
    r_ctx->px_cookie_decrypted = dpayload;

    // clean memory
    EVP_CIPHER_CTX_free(ctx);
    return c;
}

validation_result_t validate_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key) {
    if (cookie == NULL) {
        INFO(ctx->r->server, "validate_cookie: NO COOKIE");
        return NULL_COOKIE;
    }

    if (cookie->hash == NULL || strlen(cookie->hash) == 0) {
        INFO(ctx->r->server, "validate_cookie: NO SIGNING");
        return NO_SIGNING;
    }

    struct timeval te;
    gettimeofday(&te, NULL);
    long long currenttime = te.tv_sec * 1000LL + te.tv_usec / 1000;
    if (currenttime > cookie->ts) {
        INFO(ctx->r->server, "validate_cookie: COOKIE EXPIRED");
        return EXPIRED;
    }

    char signature[HASH_LEN];
    const char *signing_fields[] = { cookie->timestamp, cookie->a, cookie->b, cookie->uuid, cookie->vid, ctx->useragent } ;
    digest_cookie(cookie_key, signing_fields, sizeof(signing_fields)/sizeof(*signing_fields), signature, HASH_LEN);

    if (memcmp(signature, cookie->hash, 64) != 0) {
        INFO(ctx->r->server, "validate_cookie: SIGNATURE INVALID");
        return INVALID;
    }

    INFO(ctx->r->server, "validate_cookie: VALID");
    return VALID;
}
