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

    EC_POINT *N; /* = (Y/V^{\pi_0})^{\pi_1} = L^\beta */
    EC_POINT *Z; /* = (Y/V^{\pi_0})^\alpha = (X/U^{\pi_0})^\beta */

    BIGNUM *k; /* = H(\pi_0, X, Y, Z, N) */
};

struct pake_client_info {
    const char   *password;
    BIGNUM *pi_1; /* = H_1(user, realm, pw) */
};

struct pake_client_state {
    BIGNUM *alpha;
    EC_POINT *X;

    /* recvd from server */
    EC_POINT *server_Y;
};

struct pake_server_state {
    BIGNUM *beta;
    EC_POINT *Y;

    /* recvd from client */
    EC_POINT *client_X;
};

struct pake_info {
    struct pake_public_info  public;
    struct pake_shared_info  shared;
    struct pake_client_info  client;
    struct pake_client_state client_state;
    struct pake_server_state server_state;
    int isclient;
    int isserver;
};

int pake_server_init(struct pake_info *p, BN_CTX *ctx);
int pake_client_init(struct pake_info *p, BN_CTX *ctx);

int pake_server_init_state(struct pake_info *p, BN_CTX *ctx);
int pake_client_init_state(struct pake_info *p, BN_CTX *ctx);

int pake_compute_k(struct pake_info *p, BN_CTX *ctx);

void debug_pake_info(const struct pake_info *p);
void debug_bignum(BIGNUM *bn);
void debug_point(const EC_GROUP *G, const char *msg, const EC_POINT *P, BN_CTX *ctx);

#endif // TCPCRYPT_PAKE_H
