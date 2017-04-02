#include "px_cookie_v3_decoder.h"

#include <stdio.h>
#include <apr_strings.h>

const char *SEPERATOR = ":";

 // not really cookie v3 dependant
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


