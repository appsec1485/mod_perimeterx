#ifndef PX_COOKIE_UTILS_H
#define PX_COOKIE_UTILS_H

#include <apr_pools.h>

int parse_cookie(char *px_cookie, char **cookie_parts);
void digest_cookie(const char *cookie_key, const char **signing_fields, int sign_fields_size, char *buffer, int buffer_len);
int decode_base64(const char *s, unsigned char **o, int *len, apr_pool_t *p);

#endif
