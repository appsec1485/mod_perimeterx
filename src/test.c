#include "px_enforcer.h"

int main() {
    bool a = px_should_verify_request(NULL, NULL);
    printf("boolean: %d", a);
}

