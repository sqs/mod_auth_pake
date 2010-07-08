#include "pake.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *user, *realm, *password;
    struct pake_info pake;
    char *s;
    BN_CTX *ctx;
    
    if (argc != 4) {
        printf("usage: %s <user> <realm> <password>\n", argv[0]);
        exit(1);
    }

    user = argv[1];
    realm = argv[2];
    password = argv[3];

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    memset(&pake, '\0', sizeof(pake));

    if (!pake_client_init(&pake, ctx)) {
        printf("pake_client_init error\n");
        exit(1);
    }
    
    if (!pake_client_set_credentials(&pake, user, realm, password, ctx)) {
        printf("pake_client_set_credentials error\n");
        exit(1);
    }
    
    s = BN_bn2hex(pake.shared.pi_0);
    printf("pi_0 = %s\n", s);
    OPENSSL_free(s);

    s = EC_POINT_point2hex(pake.public.G, pake.shared.L, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("L    = %s\n", s);
    OPENSSL_free(s);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}
