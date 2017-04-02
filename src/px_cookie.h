#ifndef PX_COOKIE_H
#define PX_COOKIE_H

#include "px_types.h"

//TODO: make this the main file that handles cookie and split it to different types of cookies
//
typedef struct risk_cookie_v1_t {
    const char *timestamp;
    long long ts;
    const char *hash;
    const char *uuid;
    const char *vid;
    const char *a;
    const char *b;
    int a_val;
    int b_val;
} risk_cookie; //TODO: rename

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx);
validation_result_t validate_cookie(const risk_cookie *cookie, request_context *ctx, const char *cookie_key);

#endif
