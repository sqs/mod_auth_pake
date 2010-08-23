#include <pake/pake.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *user, *realm, *password;
    struct pake_info *pake;
    char *s;
    
    if (argc != 4) {
        printf("usage: %s <user> <realm> <password>\n", argv[0]);
        exit(1);
    }

    user = argv[1];
    realm = argv[2];
    password = argv[3];

    pake = pake_client_new();
    if (!pake_client_init(pake)) {
        printf("pake_client_init error\n");
        exit(1);
    }
    
    if (!pake_client_set_credentials(pake, user, realm, password)) {
        printf("pake_client_set_credentials error\n");
        exit(1);
    }

    printf("%s ", user);
    
    s = BN_bn2hex(pake->shared.pi_0);
    printf("%s ", s);
    OPENSSL_free(s);

    s = EC_POINT_point2hex(pake->public.G, pake->shared.L, POINT_CONVERSION_UNCOMPRESSED, pake->ctx);
    printf("%s\n", s);
    OPENSSL_free(s);
    
    return 0;
}
