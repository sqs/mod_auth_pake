#include "pake.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

static int pake_init_shared(struct pake_info *p);
static int pake_init_public(struct pake_info *p);
static int pake_server_init_state(struct pake_info *p);
static int pake_client_init_state(struct pake_info *p);

static int pake_server_compute_N_Z(struct pake_info *p, BN_CTX *ctx);
static int pake_client_compute_N_Z(struct pake_info *p, BN_CTX *ctx);

static void debug_bignum(BIGNUM *bn);
static void debug_point(const EC_GROUP *G, const char *msg, const EC_POINT *P, BN_CTX *ctx);

static int hash_bn(SHA256_CTX *sha, const BIGNUM *x);
static int get_affine_coordinates(const EC_GROUP *G,
                           const EC_POINT *P,
                           BIGNUM *x,
                           BIGNUM *y,
                           BN_CTX *ctx);

int pake_server_init(struct pake_info *p) {
    int ret = 0;

    p->isserver = 1;

    if (!pake_init_public(p)) goto err;
    if (!pake_init_shared(p)) goto err;
    if (!pake_server_init_state(p)) goto err;

    ret = 1;

 err:
    return ret;
}

int pake_client_init(struct pake_info *p) {
    int ret = 0;

    p->isclient = 1;    

    if (!pake_init_public(p)) goto err;
    if (!pake_init_shared(p)) goto err;
    if (!pake_client_init_state (p)) goto err;

    ret = 1;

 err:
    return ret;
}

/* Set $G,$ $U,$ and $V.$ */
int pake_init_public(struct pake_info *p) {
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *tmp = NULL, *order = NULL;

    p->public.G = NULL;
    p->public.U = NULL;
    p->public.V = NULL;
    p->public.username = "jsmith";
    p->public.realm = "protected area";
    p->client.password = "jsmith"; /* TODO: shouldn't need to set this in init_public */

    if (!(ctx = BN_CTX_new())) goto err;
    BN_CTX_start(ctx);
    tmp = BN_new();
    order = BN_new();
    if (!tmp || !order) goto err;

    /* set G */
    p->public.G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!p->public.G) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, ctx)) goto err;
    
    /* alloc U and V */
    p->public.U = EC_POINT_new(p->public.G);
    p->public.V = EC_POINT_new(p->public.G);
    if (!p->public.U || !p->public.V) goto err;

    /* HACK: choose U, V */
    do {
        if (!BN_rand_range(tmp, order)) goto err;
    } while (BN_is_zero(tmp));
    if (!BN_hex2bn(&tmp, "799ABC951C32825396D5EEA12C527308ECC0393621EEFC82B5B2C6AB4BA895B6")) goto err;
    if (!EC_POINT_mul(p->public.G, p->public.U, tmp, NULL, NULL, ctx)) goto err;

    do {
        if (!BN_rand_range(tmp, order)) goto err;
    } while (BN_is_zero(tmp));
    if (!BN_hex2bn(&tmp, "7417A0F2C5824875508F1524CAFA2521F49562B89D86D15530BFF792EBBB8BDD")) goto err;
    if (!EC_POINT_mul(p->public.G, p->public.V, tmp, NULL, NULL, ctx)) goto err;

    ret = 1;

 err:
    if (!ret) printf("FAIL\n");
    return ret;
}

/* Set $pi_0,$ and $L.$ Precompute $V^{\pi_0},$ $U^{\pi_0},$
   $V^{-\pi_0},$ and $U^{-\pi_0}.$ */
int pake_init_shared(struct pake_info *p) {
    int ret = 0;
    unsigned char H = 0;
    SHA512_CTX sha;
    unsigned char md[SHA512_DIGEST_LENGTH];
    BN_CTX *ctx = NULL;
    BIGNUM *tmp = NULL, *order = NULL;

    if (!(ctx = BN_CTX_new())) goto err;
    BN_CTX_start(ctx);
    order = BN_new();
    tmp = BN_new();
    if (!order || !tmp) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, ctx)) goto err;

    /* HACK: make sure we can get ~uniform distribution [bittau] */
    if (BN_num_bits(order) > 512 - 64) goto err;

    /* get pi_0 */
    /* TODO: need to concatenate with ":"s? */
    /* TODO: the server doesn't actually know the password -- only pi_0 is sent to it */
    if (!(p->shared.pi_0 = BN_new())) goto err; /* TODO: free this */
    H = 0;
    if (!SHA512_Init(&sha)) goto err;
    if (!SHA512_Update(&sha, &H, 1)) goto err;
    if (!SHA512_Update(&sha, p->public.username, 1+strlen(p->public.username))) goto err;
    if (!SHA512_Update(&sha, p->public.realm, 1+strlen(p->public.realm))) goto err;
    if (!SHA512_Update(&sha, p->client.password, 1+strlen(p->client.password))) goto err;
    if (!SHA512_Final(md, &sha)) goto err;
    if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
    if (!BN_nnmod(p->shared.pi_0, tmp, order, ctx)) goto err;
    

    /* get pi_1 */
    /* TODO: need to concatenate with ":"s? */
    /* TODO: the server doesn't actually know pi_1 -- only L is sent to it */
    if (!(p->client.pi_1 = BN_new())) goto err; /* TODO: free this */
    H = 1;
    if (!SHA512_Init(&sha)) goto err;
    if (!SHA512_Update(&sha, &H, 1)) goto err;
    if (!SHA512_Update(&sha, p->public.username, 1+strlen(p->public.username))) goto err;
    if (!SHA512_Update(&sha, p->public.realm, 1+strlen(p->public.realm))) goto err;
    if (!SHA512_Update(&sha, p->client.password, 1+strlen(p->client.password))) goto err;
    if (!SHA512_Final(md, &sha)) goto err;
    if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
    if (!BN_nnmod(p->client.pi_1, tmp, order, ctx)) goto err;
    
    /* compute V_pi_0 */
    if (!(p->shared.V_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.V_pi_0, NULL, p->public.V, p->shared.pi_0, ctx)) goto err;

    /* compute U_pi_0 */
    if (!(p->shared.U_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.U_pi_0, NULL, p->public.U, p->shared.pi_0, ctx)) goto err;

    /* compute U_minus_pi_0 */
    if (!(p->shared.U_minus_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.U_minus_pi_0, NULL, p->public.U, p->shared.pi_0, ctx)) goto err;
    if (!EC_POINT_invert(p->public.G, p->shared.U_minus_pi_0, ctx)) goto err;

    /* compute V_minus_pi_0 */
    if (!(p->shared.V_minus_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.V_minus_pi_0, NULL, p->public.V, p->shared.pi_0, ctx)) goto err;
    if (!EC_POINT_invert(p->public.G, p->shared.V_minus_pi_0, ctx)) goto err;

    /* compute L */
    if (!(p->shared.L = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.L, p->client.pi_1, NULL, NULL, ctx)) goto err;

    ret = 1;

 err:
    if (!ret) {
        BN_clear(p->shared.pi_0);
        BN_clear(p->client.pi_1); /* TODO: shouldn't access pi_1 here in init_shared */
    }

    bzero(md, sizeof(md));
    bzero(&sha, sizeof(sha));

    if (order) BN_free(order);
    if (tmp) BN_clear_free(tmp);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

/* Choose $\beta \in \mathbf{Z}_q$ at random, and compute $Y = g^\beta
   V^{\pi_0}.$ */
int pake_server_init_state(struct pake_info *p) {
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL;
    EC_POINT *Y2 = NULL;
    SHA256_CTX sha;

    if (!(ctx = BN_CTX_new())) goto err;
    BN_CTX_start(ctx);
    order = BN_new();
    p->server_state.beta = BN_new();
    p->server_state.Y = EC_POINT_new(p->public.G);
    Y2 = EC_POINT_new(p->public.G);
    if (!order || !p->server_state.beta || !p->server_state.Y || !Y2) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, ctx)) goto err;
    if (!SHA256_Init(&sha)) goto err;
    if (!hash_bn(&sha, p->shared.pi_0)) goto err;
    
    /* choose beta */
    do {
        if (!BN_rand_range(p->server_state.beta, order)) goto err;
    } while (BN_is_zero(p->server_state.beta));

    /* compute Y */
    if (!EC_POINT_mul(p->public.G, Y2, p->server_state.beta, NULL, NULL, ctx)) goto err;
    debug_point(p->public.G, "server Y2", Y2, ctx);
    if (!EC_POINT_add(p->public.G, p->server_state.Y, Y2, p->shared.V_pi_0, ctx)) goto err;
    debug_point(p->public.G, "server Y", p->server_state.Y, ctx);

    ret = 1;

 err:
    if (ctx) { BN_CTX_end(ctx); BN_CTX_free(ctx); }
    if (order) BN_free(order);
    /* others already free */
    bzero(&sha, sizeof(sha));

    return ret;
}

/* Choose $\beta in \mathbf{Z}_q$ at random, and compute $X=g^\alpha
   U^{\pi_0}.$ */
int pake_client_init_state(struct pake_info *p) {
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL;
    EC_POINT *X2 = NULL;
    SHA256_CTX sha;

    if (!(ctx = BN_CTX_new())) goto err;
    BN_CTX_start(ctx);
    order = BN_new();
    p->client_state.alpha = BN_new();
    p->client_state.X = EC_POINT_new(p->public.G);
    X2 = EC_POINT_new(p->public.G);
    if (!order || !p->client_state.alpha || !p->client_state.X || !X2) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, ctx)) goto err;
    if (!SHA256_Init(&sha)) goto err;
    if (!hash_bn(&sha, p->shared.pi_0)) goto err;
    
    /* choose beta */
    do {
        if (!BN_rand_range(p->client_state.alpha, order)) goto err;
    } while (BN_is_zero(p->client_state.alpha));

    /* compute Y */
    if (!EC_POINT_mul(p->public.G, X2, p->client_state.alpha, NULL, NULL, ctx)) goto err;
    debug_point(p->public.G, "client X2", X2, ctx);
    if (!EC_POINT_add(p->public.G, p->client_state.X, X2, p->shared.U_pi_0, ctx)) goto err;
    debug_point(p->public.G, "client X", p->client_state.X, ctx);

    ret = 1;

 err:
    if (ctx) { BN_CTX_end(ctx); BN_CTX_free(ctx); }
    if (order) BN_free(order);
    /* others already free */
    bzero(&sha, sizeof(sha));

    return ret;
}

/* Compute $N = L^\beta$ and $Z = (X/U^{\pi_0})^\beta.$ */
int pake_server_compute_N_Z(struct pake_info *p, BN_CTX *ctx) {
    int ret = 0;
    EC_POINT *X2 = NULL;

    if (!(X2 = EC_POINT_new(p->public.G))) goto err;

    /* Compute $N = L^\beta.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.N, NULL, p->shared.L, p->server_state.beta, ctx)) goto err;

    /* Compute $Z = (X/U^{\pi_0})^\beta.$ */
    if (!EC_POINT_add(p->public.G, X2, p->server_state.client_X, p->shared.U_minus_pi_0, ctx)) goto err;
    if (!EC_POINT_mul(p->public.G, p->shared.Z, NULL, X2, p->server_state.beta, ctx)) goto err;
    
    ret = 1;

 err:
    if (X2) EC_POINT_clear_free(X2); /* TODO: necessary? */

    return ret;
}

/* Compute $N = (Y/V^{\pi_0})^{\pi_1}$ and $Z = (Y/V^{\pi_0})^{\pi_1}.$ */
int pake_client_compute_N_Z(struct pake_info *p, BN_CTX *ctx) {
    int ret = 0;
    EC_POINT *Y2 = NULL;

    if (!(Y2 = EC_POINT_new(p->public.G))) goto err;

    /* Compute $Y2 = Y/V^{\pi_0}.$ */
    if (!EC_POINT_add(p->public.G, Y2, p->client_state.server_Y, p->shared.V_minus_pi_0, ctx)) goto err;

    /* Compute $N = (Y/V^{\pi_0})^{\pi_1} = Y2^{\pi_1}.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.N, NULL, Y2, p->client.pi_1, ctx)) goto err;

    /* Compute $Z = (Y/V^{\pi_0})^\alpha = Y2^\alpha.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.Z, NULL, Y2, p->client_state.alpha, ctx)) goto err;
    
    ret = 1;

 err:
    if (Y2) EC_POINT_clear_free(Y2); /* TODO: necessary? */

    return ret;    
}

/* Compute $k = H(\pi_0, X, Y, Z, N).$ */
int pake_compute_k(struct pake_info *p) {
    int ret = 0;

    if (p->isserver) {
        if (!pake_server_compute_N_Z(p, NULL)) goto err;
    } else {
        if (!pake_client_compute_N_Z(p, NULL)) goto err;
    }
    
    ret = 1;
 err:

    return ret;
}

void debug_pake_info(const struct pake_info *p) {
    const char *t = "\t";

    printf("struct pake_info {\n");
    
    /* public */
    printf("%sEC_GROUP G     = %s\n", t,     "<...>");
    printf("%sEC_POINT U     = %s\n", t,     "<...>");
    printf("%sEC_POINT V     = %s\n", t,     "<...>");
    printf("%schar *username = \"%s\"\n", t, p->public.username);
    printf("%schar *realm    = \"%s\"\n", t, p->public.realm);

    printf("\n%s/*** pake_shared_info ***/\n", t);
    printf("%spi_0 =  ", t); debug_bignum(p->shared.pi_0); printf("\n");
    printf("%sL    = ", t); debug_point(p->public.G, "", p->shared.L, NULL);

    if (p->isclient) {
        printf("\n%s/*** pake_client_info ***/\n", t);
        printf("%spassword = \"%s\"\n", t, p->client.password);
        printf("%spi_0     =  ", t); debug_bignum(p->client.pi_1); printf("\n");

        printf("\n%s/*** pake_client_state ***/\n", t);
        printf("%salpha = ", t); debug_bignum(p->client_state.alpha); printf("\n");
        printf("%sX = ", t); debug_point(p->public.G, "", p->client_state.X, NULL); printf("\n");
    }

    if (p->isserver) {
        printf("\n%s/*** pake_server_state ***/\n", t);
        printf("%sbeta =  ", t); debug_bignum(p->server_state.beta); printf("\n");
        printf("%sY    = ", t); debug_point(p->public.G, "", p->server_state.Y, NULL);
    }

    printf("}\n");
}

void debug_bignum(BIGNUM *bn) {
    if (!bn) goto err;

    int size = BN_num_bytes(bn);
    unsigned char *out_bn = alloca(size);
    int i;

    if (!BN_bn2bin(bn, out_bn)) goto err;

    for (i=0; i<size; i++) {
        if (i && i % 8 == 0) printf(" ");
        printf("%02hhX", out_bn[i]);
    }

    return;
 err:
    printf("debug_bignum ERROR\n");
}

void debug_point(const EC_GROUP *G,
                 const char *message,
                 const EC_POINT *P,
                 BN_CTX *ctx) {
  BIGNUM *x = BN_new(), *y = BN_new();
  int sx, sy;
  unsigned char *out_x = NULL, *out_y = NULL;
  if (!P) goto err;
  if (!x || !y) goto err;
  if (!get_affine_coordinates(G, P, x, y, ctx)) goto err;

  sx = BN_num_bytes(x);
  sy = BN_num_bytes(y);
  
  if (strlen(message)) {
      printf("*** %s: ", message);
  }

  printf("(");
  debug_bignum(x);
  printf(", ");
  debug_bignum(y);
  printf(")\n");

  goto done;

 err:
  printf("debug_point %sERROR\n", strlen(message) ? message : "");

 done:
  if (out_x) bzero(out_x, sx);
  if (out_y) bzero(out_y, sy);
  if (x) BN_clear_free(x);
  if (y) BN_clear_free(y);
}

int get_affine_coordinates(const EC_GROUP *G,
                           const EC_POINT *P,
                           BIGNUM *x,
                           BIGNUM *y,
                           BN_CTX *ctx) {
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(G))
      == NID_X9_62_prime_field) {
    return EC_POINT_get_affine_coordinates_GFp (G, P, x, y, ctx);
  } else { /* NID_X9_62_characteristic_two_field */
    return EC_POINT_get_affine_coordinates_GF2m(G, P, x, y, ctx);
  }
}

int hash_bn(SHA256_CTX *sha, const BIGNUM *x) {
  /* allocate space */
  int size = BN_num_bytes(x), ret = 0;
  if (size <= 0 || size >= 256) return 0;
  unsigned char *tmp = (unsigned char *) alloca(size+1);

  /* first byte is size to ensure parseability */
  *tmp = (unsigned char) size;

  /* convert to bytes and hash it */
  if (!BN_bn2bin(x, tmp+1)) goto err;
  ret = SHA256_Update(sha, (const void *) tmp, size+1);

 err:
  bzero(tmp, size+1);
  return ret;
}
