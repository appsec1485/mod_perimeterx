#ifndef PX_ERRORS_H
#define PX_ERRORS_H

// cookie
#define PX_SUCCESS               0
#define COOKIE_ERR_JSON_LOAD     1
#define COOKIE_ERR_JSON_UNPACK   2
#define COOKIE_ERR_MEM_ALLOC     3


const char *error_string(int error_code) {
    switch(error_code) {
        case COOKIE_ERR_JSON_LOAD: ""
        case COOKIE_ERR_JSON_UNPACK: ""
        case COOKIE_ERR_MEM_ALLOC: ""
    }
}


#endif
