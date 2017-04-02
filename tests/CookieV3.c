#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include "CuTest.h"

#include "../src/px_cookie_v3_decoder.h"

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

CuSuite *CookieV3SuiteGet() {
    CuSuite *suite = CuSuiteNew();

    // parse cookie
    SUITE_ADD_TEST(suite, TestCookieV3_ParseNullCookie);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseValidCookieFormat);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat1);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat2);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseInvalidCookieFormat3);
    SUITE_ADD_TEST(suite, TestCookieV3_ParseNullCookieParts);

    return suite;
}
