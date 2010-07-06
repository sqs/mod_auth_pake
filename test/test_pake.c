#include "pake.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>

void test_pake() {
    struct pake_info ps, pc;
    BN_CTX *ctx = NULL;

    memset(&ps, 0, sizeof(ps));
    memset(&pc, 0, sizeof(pc));
    assert(ctx = BN_CTX_new());
    BN_CTX_start(ctx);

    assert(pake_server_init(&ps, ctx));
    assert(pake_client_init(&pc, ctx));

    /* TODO: HACK: fake client-server interaction */
    ps.server_state.client_X = pc.client_state.X;
    pc.client_state.server_Y = ps.server_state.Y;
    
    assert(pake_compute_k(&ps, ctx));
    assert(pake_compute_k(&pc, ctx));

    debug_point(ps.public.G, "server N", ps.shared.N, ctx);
    debug_point(pc.public.G, "client N", pc.shared.N, ctx);
    debug_point(ps.public.G, "server Z", ps.shared.Z, ctx);
    debug_point(pc.public.G, "client Z", pc.shared.Z, ctx);

    assert(EC_POINT_cmp(ps.public.G, ps.shared.N, pc.shared.N, ctx) == 0);
    assert(EC_POINT_cmp(ps.public.G, ps.shared.Z, pc.shared.Z, ctx) == 0);


    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
