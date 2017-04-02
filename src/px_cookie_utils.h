#ifndef PX_COOKIE_UTILS_H
#define PX_COOKIE_UTILS_H

void digest_cookie(const char *cookie_key, const char **signing_fields, int sign_fields_size, char *buffer, int buffer_len);

#endif
