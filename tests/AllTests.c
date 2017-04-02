#include <stdio.h>
#include "CuTest.h"

// Getting all wanted suites
/*CuSuite *CookieV3SuiteGet();*/
CuSuite *CookieUtilsSuiteGet();

// Suites runner
void RunAllTests() {
    CuString *output = CuStringNew();
    /*CuSuite *cookie_v3_suite = CuSuiteNew();*/
    CuSuite *cookie_utils_suite = CuSuiteNew();

    /*CuSuiteAddSuite(cookie_v3_suite, CookieV3SuiteGet());*/
    /*CuSuiteAddSuite(cookie_utils_suite, CookieUtilsSuiteGet());*/

    /*CuSuiteRun(cookie_v3_suite);*/
    /*CuSuiteRun(cookie_utils_suite);*/

    /*CuSuiteSummary(cookie_v3_suite, output);*/
    /*CuSuiteDetails(cookie_v3_suite, output);*/
    /*printf("Cookie V3 Suite %s\n", output->buffer);*/

    CuSuiteSummary(cookie_utils_suite, output);
    CuSuiteDetails(cookie_utils_suite, output);
    printf("Cookie Utils Suite %s\n", output->buffer);
}

int main(void) {
    RunAllTests();
    return 0;
}
