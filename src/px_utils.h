#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>

#include "px_types.h"

struct response_t {
    char* data;
    size_t size;
    server_rec *server;
};

size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream);
const char *extract_first_ip(apr_pool_t *p, const char *ip);
const char *get_request_ip(const request_rec *r, const px_config *conf);

#endif
