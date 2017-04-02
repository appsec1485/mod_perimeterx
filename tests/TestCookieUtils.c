#include <stdio.h>
#include <stdlib.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include "CuTest.h"

#include "../src/px_cookie_utils.h"

void TestCookieV3_ParseNullCookie(CuTest *tc) {
    int res = parse_cookie(NULL, NULL);
    CuAssertIntEquals(tc, -1, -1);
}

void TestCookieV3_ParseNullCookieParts(CuTest *tc) {
    int res = parse_cookie("abc", NULL);
    CuAssertIntEquals(tc, -1, -1);
}

void TestCookieV3_ParseValidCookieFormat(CuTest *tc) {
    const char *cookie = "a:b:c:d";
    char *px_cookie = malloc(sizeof(char) );
    char **cookie_parts = (char**)malloc(sizeof(char*) * 4);
    strcpy(px_cookie, cookie);
    int res = parse_cookie(px_cookie, cookie_parts);

    CuAssertIntEquals(tc, 4, 4);
    CuAssertStrEquals(tc, cookie_parts[0], "a");
    CuAssertStrEquals(tc, cookie_parts[1], "b");
    CuAssertStrEquals(tc, cookie_parts[2], "c");
    CuAssertStrEquals(tc, cookie_parts[3], "d");
}

void TestCookieV3_ParseInvalidCookieFormat1(CuTest *tc) {
    const char *cookie = "a:b:c:";
    char *px_cookie = malloc(sizeof(char) );
    char **cookie_parts = (char**)malloc(sizeof(char*) * 4);
    strcpy(px_cookie, cookie);
    int res = parse_cookie(px_cookie, cookie_parts);

    CuAssertIntEquals(tc, 3, 3);
    CuAssertStrEquals(tc, cookie_parts[0], "a");
    CuAssertStrEquals(tc, cookie_parts[1], "b");
    CuAssertStrEquals(tc, cookie_parts[2], "c");
}

void TestCookieV3_ParseInvalidCookieFormat2(CuTest *tc) {
    const char *cookie = "a:b:c";
    char *px_cookie = malloc(sizeof(char) );
    char **cookie_parts = (char**)malloc(sizeof(char*) * 4);
    strcpy(px_cookie, cookie);
    int res = parse_cookie(px_cookie, cookie_parts);

    CuAssertIntEquals(tc, 3, 3);
    CuAssertStrEquals(tc, cookie_parts[0], "a");
    CuAssertStrEquals(tc, cookie_parts[1], "b");
    CuAssertStrEquals(tc, cookie_parts[2], "c");
}

void TestCookieV3_ParseInvalidCookieFormat3(CuTest *tc) {
    const char *cookie = "abcd";
    char *px_cookie = malloc(sizeof(char) );
    char **cookie_parts = (char**)malloc(sizeof(char*) * 4);
    strcpy(px_cookie, cookie);
    int res = parse_cookie(px_cookie, cookie_parts);

    CuAssertIntEquals(tc, 1, 1);
    CuAssertStrEquals(tc, cookie_parts[0], "abcd");
}

void TestCookieUtils_DigestNoExtraFields(CuTest *cu) {

    const char *hmac = "f304c11274cabc93abe79f3abb848b94026d3e1c9a49071ea96fbece9b9f2bb0";
    const char *cookie_key = "secret_key"; // change to global cookie key
    const char **signing_fields = { NULL };

    char *buffer = malloc(sizeof(char) * 64);

    digest_cookie(cookie_key, signing_fields, 0, buffer, 65);
    CuAssertStrEquals(cu, hmac, buffer);
}

void TestCookieUtils_DigestWithExtraFields(CuTest *cu) {

    const char *hmac = "694606ba3034ce6134b076a3bf5a23d87a924b1780a0b12309bfb95006b3fdb3";
    const char *cookie_key = "secret_key"; // change to global cookie key
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
    unsigned char *payload;
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
    unsigned char *payload;
    const char *base64_str = NULL;
    const char *decoded_str = "perimeterx";

    int res = decode_base64(base64_str, &payload, &len, p);
    CuAssertIntEquals(cu, -1, res);

}

void TestDecodeCookie_InvalidCookieFormat(CuTest *cu) {
    const char *cookie_key = "perimeterx";
    const char *cookie_v3 = "thisisnotavalidcookie";
}

/*const char *decode_cookie(const char *px_cookie, const char *cookie_key, char **cookie_parts, int cookie_parts_size, apr_pool_t *pool) {*/

void TestDecodeCookie_InvalidCookieIterations(CuTest *cu) {
    const char *cookie_key = "perimeterx";
    const char *cookie_v3 = "884d9e837ae665dea46ce86f53391670db222727304c6dff34bfbaba1cce316c:ia+bM9sdJyVfx2rWUDoKTw1TKisp5LRB8Tq07axuOzaR6X50nqTs/nKtxGdaw5wPxLAhuNGuxjrGmfIZ4X+vYw==:thisisnotanumber:t8FTVaSKbDKUHOUxpKGVKYEMH7AY3je6RxmcHF0mApgHStrg3kEEUxTJEq2iiNj9z2HA2IhsUEsnooCj0A7qQoWTXAO3pPSyHyoK3KNY27k8HF4teuTUVmOOdRkSSObBFCrI8idmrJEKMfZMxzc68F2QbGN2a8aLZZaTh929cdo="
}

void TestDecodeCookie_HugeIterationsNumber(CuTest *cu) {
    const char *cookie_key = "perimeterx";
    const char *cookie_v3 = "884d9e837ae665dea46ce86f53391670db222727304c6dff34bfbaba1cce316c:ia+bM9sdJyVfx2rWUDoKTw1TKisp5LRB8Tq07axuOzaR6X50nqTs/nKtxGdaw5wPxLAhuNGuxjrGmfIZ4X+vYw==:100000000:t8FTVaSKbDKUHOUxpKGVKYEMH7AY3je6RxmcHF0mApgHStrg3kEEUxTJEq2iiNj9z2HA2IhsUEsnooCj0A7qQoWTXAO3pPSyHyoK3KNY27k8HF4teuTUVmOOdRkSSObBFCrI8idmrJEKMfZMxzc68F2QbGN2a8aLZZaTh929cdo="
}

void TestDecodeCookie_ValidV3Cookie(CuTest *cu) {
    const char *cookie_key = "perimeterx";
    const char *cookie_v3 = "884d9e837ae665dea46ce86f53391670db222727304c6dff34bfbaba1cce316c:ia+bM9sdJyVfx2rWUDoKTw1TKisp5LRB8Tq07axuOzaR6X50nqTs/nKtxGdaw5wPxLAhuNGuxjrGmfIZ4X+vYw==:1000:t8FTVaSKbDKUHOUxpKGVKYEMH7AY3je6RxmcHF0mApgHStrg3kEEUxTJEq2iiNj9z2HA2IhsUEsnooCj0A7qQoWTXAO3pPSyHyoK3KNY27k8HF4teuTUVmOOdRkSSObBFCrI8idmrJEKMfZMxzc68F2QbGN2a8aLZZaTh929cdo="

}

/*const char *decode_cookie(const char *px_cookie, const char *cookie_key, char **cookie_parts, int cookie_parts_size, apr_pool_t *pool) {*/

CuSuite *CookieUtilsSuiteGet() {
    CuSuite *suite = CuSuiteNew();

    // parse cookie
    SUITE_ADD_TEST(suite, TestCookieV3_ParseNullCookie);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseValidCookieFormat);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat1);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat2);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat3);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseNullCookieParts);

    // digest
    SUITE_ADD_TEST(suite, TestCookieUtils_DigestNoExtraFields);
    SUITE_ADD_TEST(suite, TestCookieUtils_DigestWithExtraFields);

    // base64 decode
    SUITE_ADD_TEST(suite, TestCookieUtils_ValidBase64Decode);
    SUITE_ADD_TEST(suite, TestCookieUtils_InvalidBase64Decode);

    return suite;
}
