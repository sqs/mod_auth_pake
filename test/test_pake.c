#include "pake.h"
#include <stdio.h>
#include <string.h>

void test_pake_server() {
    struct pake_info p;
    memset(&p, 0, sizeof(p));

    pake_server_init(&p);
}

void test_pake_client() {
    struct pake_info p;
    memset(&p, 0, sizeof(p));

    pake_client_init(&p);
}
