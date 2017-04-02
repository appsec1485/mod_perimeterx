#ifndef PX_COOKIE_V3_H
#define PX_COOKIE_V3_H

typedef struct risk_cookie_v3_t {
    const char *timestamp;
    long long ts;
    const char *uuid;
    const char *vid;
    const char *action;
} risk_cookie_v3;

int parse_cookie(char *px_cookie, char **cookie_parts);
int decrypt_cookie(const char *px_cookie, char **cookie_parts, int argc);
int verify_cookie(const char *px_cookie, char **cookie_parts, int argc);

#endif
