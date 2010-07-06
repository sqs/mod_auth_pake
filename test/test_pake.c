#include "pake.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    printf("tcpcrypt http pake\n\n");

    struct pake_info p;

    printf("pake_init_server:\n");
    memset(&p, 0, sizeof(p));
    if (pake_init_server(&p)) debug_pake_info(&p);

    printf("pake_init_client:\n");
    memset(&p, 0, sizeof(p));
    if (pake_init_client(&p)) debug_pake_info(&p);

    return 0;
}

