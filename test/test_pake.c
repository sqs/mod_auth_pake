#include "pake.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>

void test_pake_server() {
    struct pake_info p;
    BN_CTX *ctx = NULL;

    memset(&p, 0, sizeof(p));
    assert(ctx = BN_CTX_new());
    BN_CTX_start(ctx);

    pake_server_init(&p, ctx);
    pake_client_init_state(&p, ctx);
    assert(pake_compute_k(&p, ctx));

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void test_pake_client() {
    struct pake_info p;
    BN_CTX *ctx = NULL;

    memset(&p, 0, sizeof(p));
    assert(ctx = BN_CTX_new());
    BN_CTX_start(ctx);

    memset(&p, 0, sizeof(p));

    pake_client_init(&p, ctx);
    pake_server_init_state(&p, ctx);
    assert(pake_compute_k(&p, ctx));

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
