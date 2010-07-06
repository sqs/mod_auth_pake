#ifndef TCPCRYPT_PAKE_H
#define TCPCRYPT_PAKE_H

#include <openssl/bn.h>
#include <openssl/ec.h>

struct pake_public_info {
    EC_GROUP *G;
    EC_POINT *U;
    EC_POINT *V;
    char     *username;
    char     *realm;
};

struct pake_shared_info {
    BIGNUM   *pi_0; /* = H_0(user, realm, pw) */
    EC_POINT *L; /* = g^{\pi_0} */

    /* computed values */
    EC_POINT *V_pi_0;
    EC_POINT *U_pi_0;
    EC_POINT *V_minus_pi_0;
    EC_POINT *U_minus_pi_0;
};

struct pake_client_info {
    const char   *password;
    BIGNUM *pi_1; /* = H_1(user, realm, pw) */
};

struct pake_client_state {
    BIGNUM *alpha;
    EC_POINT *X;
};

struct pake_server_state {
    BIGNUM *beta;
    EC_POINT *Y;
};

struct pake_info {
    struct pake_public_info  public;
    struct pake_shared_info  shared;
    struct pake_client_info  client;
    struct pake_client_state client_state;
    struct pake_server_state server_state;
};
int pake_init_server(struct pake_info *p);
int pake_init_client(struct pake_info *p);

#endif // TCPCRYPT_PAKE_H
