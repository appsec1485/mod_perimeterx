#include <stdio.h>
#include <stdlib.h>
#include <apr_pools.h>

#include "CuTest.h"

#include "../src/px_cookie_utils.h"

void TestCookieUtils_DigestNoExtraFields(CuTest *cu) {

    const char *hmac = "f304c11274cabc93abe79f3abb848b94026d3e1c9a49071ea96fbece9b9f2bb0";
    const char *cookie_key = "secret_key";
    const char **signing_fields = { NULL };

    char *buffer = malloc(sizeof(char) * 64);

    digest_cookie(cookie_key, signing_fields, 0, buffer, 65);
    CuAssertStrEquals(cu, hmac, buffer);
}

void TestCookieUtils_DigestWithExtraFields(CuTest *cu) {

    const char *hmac = "694606ba3034ce6134b076a3bf5a23d87a924b1780a0b12309bfb95006b3fdb3";
    const char *cookie_key = "secret_key";
    const char *signing_fields[] = { "a", "b", "c" };

    char *buffer = malloc(sizeof(char) * 64);

    digest_cookie(cookie_key, signing_fields, 3, buffer, 65);
    CuAssertStrEquals(cu, hmac, buffer);
}

void TestCookieUtils_ValidBase64Decode(CuTest *cu) {

    apr_pool_t *p;

    apr_initialize();
    apr_pool_create(&p, NULL);

    int len;
    char *payload;
    const char *base64_str = "cGVyaW1ldGVyeA==";
    const char *decoded_str = "perimeterx";

    int res = decode_base64(base64_str, &payload, &len, p);
    CuAssertIntEquals(cu, 0, res);
    CuAssertStrEquals(cu, decoded_str, payload);
}

void TestCookieUtils_InvalidBase64Decode(CuTest *cu) {

    apr_pool_t *p;

    apr_initialize();
    apr_pool_create(&p, NULL);

    int len;
    char *payload;
    const char *base64_str = NULL;
    const char *decoded_str = "perimeterx";

    int res = decode_base64(base64_str, &payload, &len, p);
    CuAssertIntEquals(cu, -1, res);

}

CuSuite *CookieUtilsSuiteGet() {
    CuSuite *suite = CuSuiteNew();

    // digest
    SUITE_ADD_TEST(suite, TestCookieUtils_DigestNoExtraFields);
    SUITE_ADD_TEST(suite, TestCookieUtils_DigestWithExtraFields);

    // base64 decode
    SUITE_ADD_TEST(suite, TestCookieUtils_ValidBase64Decode);
    SUITE_ADD_TEST(suite, TestCookieUtils_InvalidBase64Decode)

    return suite;
}
