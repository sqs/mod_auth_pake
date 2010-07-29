#include "apache2_module.h"
#include "apache2_module_init.h"
#include "crypto.h"
#include "tcpcrypt_session.h"
#include <assert.h>

#define APLOG(s...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, s)
#define LOG_PAKE 1

int authorize_stage1(request_rec *r, auth_pake_config_rec *conf, auth_pake_header_rec *resp);
int authorize_stage2(request_rec *r, auth_pake_config_rec *conf, auth_pake_header_rec *resp);

int parse_authorization_header(request_rec *r, auth_pake_header_rec *resp);
void make_stage1_auth_challenge(request_rec *r,
                                const auth_pake_config_rec *conf,
                                auth_pake_header_rec *resp);
void make_stage2_auth_challenge(request_rec *r,
                                const auth_pake_config_rec *conf,
                                auth_pake_header_rec *resp);
static authn_status set_user_pake_info(request_rec *r, auth_pake_config_rec *conf, const char *username, const char *pi_0_hex, const char *L_hex, int make_dummy);

/* Get the request-uri (before any subrequests etc are initiated) and
 * initialize the request_config.
 */
static int make_header_rec(request_rec *r)
{
    auth_pake_header_rec *resp;

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    resp = apr_pcalloc(r->pool, sizeof(auth_pake_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    resp->auth_ok = 0;
    resp->method = r->method;
    ap_set_module_config(r->request_config, &auth_pake_module, resp);

    parse_authorization_header(r, resp);

    return DECLINED;
}

/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists */
int parse_authorization_header(request_rec *r, auth_pake_header_rec *resp)
{
    const char *auth_line;
    apr_size_t l;
    int vk = 0, vv = 0;
    char *key, *value;

    auth_line = apr_table_get(r->headers_in, "Authorization");
    if (!auth_line) {
        resp->auth_hdr_sts = NO_HEADER;
        return !OK;
    }

    int header_parse_ok = pake_http_header_parse(&resp->hdr, 
                                                 auth_line, HTTP_AUTHORIZATION);

    if (!resp->hdr.auth_name || strcasecmp(resp->hdr.auth_name, "PAKE")) {
        resp->auth_hdr_sts = NOT_PAKE_AUTH;
        return !OK;
    }

    if (!header_parse_ok) {
        resp->auth_hdr_sts = INVALID;
        return !OK;
    }

    /* set which stage we're on */
    resp->auth_hdr_sts = 
        resp->hdr.type == PAKE_HTTP_AUTHORIZATION_STAGE1 ? VALID_STAGE1 : VALID_STAGE2;

    return OK;
}

/*
 * Authorization header verification code
 */

static BIGNUM *make_beta(unsigned char *secret) {
    BIGNUM *beta;
    SHA512_CTX sha;
    long tcpcrypt_sid;
    unsigned char md[SHA512_DIGEST_LENGTH];

    beta = BN_new();
    assert(beta);

    tcpcrypt_sid = tcpcrypt_get_sid();

    assert(SHA512_Init(&sha));
    assert(SHA512_Update(&sha, &tcpcrypt_sid, sizeof(tcpcrypt_sid)));
    assert(SHA512_Update(&sha, secret, SECRET_LEN));
    assert(SHA512_Final(md, &sha));

    assert(BN_bin2bn(md, SHA512_DIGEST_LENGTH, beta));
    return beta;
}

/* Gets pake auth info for `user` (pi_0, pi_1, username) and stores it in `conf`. */
static authn_status get_user_pake_info(request_rec *r, const char *username,
                                       auth_pake_config_rec *conf)
{   
    BIGNUM *beta;
    conf->pake = pake_server_new();
    /* TODO: error checking and free if error */

    /* make beta = H(sid, auth_pake_secret) */
    beta = make_beta(auth_pake_secret);
    assert(beta);

    if (!pake_server_init(conf->pake, beta)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "auth_pake: couldn't init pake: %s", r->uri);
        return AUTH_GENERAL_ERROR;
    }

    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    apr_status_t status;
    char *file_pi_0 = NULL, *file_L = NULL;

    /* following code to read file is from mod_authn_file.c */
    status = ap_pcfg_openfile(&f, r->pool, conf->pakefile);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "could not open PAKEFile: %s", conf->pakefile);
        return AUTH_GENERAL_ERROR;
    }

    while(!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *rpw, *w;
            
        /* Skip # or blank lines. */
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }

        rpw = l;
        w = ap_getword(r->pool, &rpw, ' ');
            
        if (!strcmp(username, w)) {
            file_pi_0 = ap_getword(r->pool, &rpw, ' ');
            file_L = ap_getword(r->pool, &rpw, ' ');
            break;
        }
    }
    ap_cfg_closefile(f);

    if (!file_pi_0 || !file_L) {
        return AUTH_USER_NOT_FOUND;
    }

    return set_user_pake_info(r, conf, username, file_pi_0, file_L, 0);
}

static authn_status set_user_pake_info(request_rec *r, auth_pake_config_rec *conf, const char *username, const char *pi_0_hex, const char *L_hex, int make_dummy) {
    BIGNUM *pi_0 = NULL, *order = NULL, *tmp = NULL;
    EC_POINT *L = NULL;

    if (LOG_PAKE) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "--------------- username = '%s'", username);

    pi_0 = BN_new();
    L = EC_POINT_new(conf->pake->public.G);

    assert(conf->pake->public.G);

    if (make_dummy) {
        /* So that we don't leak user membership info, pretend this user exists
           and make a fake pi_0 and L for the user so we can proceed to stage2
           (it will never succeed, of course). */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "making dummy pi_0 and L for username '%s'", username);
        
        /* make dummy pi_0 */
        order = BN_new(); /* TODO(sqs): ret val check */
        EC_GROUP_get_order(conf->pake->public.G, order, conf->bn_ctx);
        do {
            assert(BN_rand_range(pi_0, order));
        } while (BN_is_zero(pi_0));
        
        /* make dummy L */
        tmp = BN_new();
        do {
            assert(BN_rand_range(tmp, order));
        } while (BN_is_zero(tmp));
        assert(EC_POINT_mul(conf->pake->public.G, L, tmp, NULL, NULL, conf->bn_ctx));
        
        BN_free(tmp);
        BN_free(order);
    } else {
        assert(BN_hex2bn(&pi_0, pi_0_hex));

        EC_POINT_hex2point(conf->pake->public.G, L_hex, L, conf->bn_ctx);
        assert(L);
    }

        
    if (LOG_PAKE) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                                "L = %s, pi_0 = %s", 
                                EC_POINT_point2hex(conf->pake->public.G, L,
                                                   POINT_CONVERSION_UNCOMPRESSED,
                                                   conf->bn_ctx),
                                BN_bn2hex(pi_0));

    if (!pake_server_set_credentials(conf->pake, username, 
                                     conf->realm, pi_0, L)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "auth_pake: couldn't set server credentials: %s", r->uri);
        return AUTH_GENERAL_ERROR;
    }

    return AUTH_USER_FOUND;
}


/* Determine user ID, and check if the attributes are correct. */

static int authenticate_pake_user(request_rec *r)
{
    auth_pake_config_rec *conf;
    auth_pake_header_rec *resp;
    request_rec       *mainreq;
    const char        *t;
    int                res;

    /* do we require PAKE auth for this URI? */

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "PAKE")) {
        return DECLINED;
    }

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* get the client response and mark */

    mainreq = r;
    while (mainreq->main != NULL) {
        mainreq = mainreq->main;
    }
    while (mainreq->prev != NULL) {
        mainreq = mainreq->prev;
    }
    resp = (auth_pake_header_rec *) ap_get_module_config(mainreq->request_config,
                                                      &auth_pake_module);
    resp->needed_auth = 1;

    /* get our conf */

    conf = (auth_pake_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &auth_pake_module);

    r->user         = (char *) resp->hdr.username;
    r->ap_auth_type = (char *) "PAKE";


    /* check for existence and syntax of Authorization header */
    if (resp->auth_hdr_sts == NOT_PAKE_AUTH) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: client used wrong authentication scheme "
                      "`%s': %s", resp->hdr.auth_name, r->uri);
        make_stage1_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    } else if (resp->auth_hdr_sts == INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: malformed header: %s",
                      r->uri);
        make_stage1_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    } else if (resp->auth_hdr_sts == VALID_STAGE1) {
        return authorize_stage1(r, conf, resp);
    } else if (resp->auth_hdr_sts == VALID_STAGE2) {
         return authorize_stage2(r, conf, resp);
    } else {
        /* No Authorize header. */
        if (conf->auth_optional) {
            r->user = "";
            return OK;
        } else {
            make_stage1_auth_challenge(r, conf, resp);
            return HTTP_UNAUTHORIZED;
        }
    }
}

int authorize_stage1(request_rec *r, auth_pake_config_rec *conf, auth_pake_header_rec *resp) {
    authn_status       return_code;

    /* check realm */
    if (strcmp(resp->hdr.realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: realm mismatch - got `%s' but expected `%s'",
                      resp->hdr.realm, conf->realm);
        make_stage1_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    } 

    return_code = get_user_pake_info(r, r->user, conf);

    if (return_code == AUTH_USER_FOUND || return_code == AUTH_USER_NOT_FOUND) {
        /* Send a dummy stage2 back if the user isn't found, so that we don't
           leak membership information. */
        if (return_code == AUTH_USER_NOT_FOUND) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_pake: user `%s' in realm `%s' not found: %s",
                          r->user, conf->realm, r->uri);
            r->user = NULL;
            set_user_pake_info(r, conf, "mod_auth_pake", NULL, NULL, 1);
            /* TODO(sqs): this could still conflict if a user is named
               mod_auth_pake */
        }

        make_stage2_auth_challenge(r, conf, resp);

        if (conf->auth_optional) {
            return HTTP_NO_CONTENT;
        } else {
            return HTTP_UNAUTHORIZED;
        }
    } else if (return_code == AUTH_DENIED) {
        /* authentication denied in the provider before attempting a match */
        /* TODO(sqs): When does this occur? Make sure this doesn't leak
           membership information. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: user `%s' in realm `%s' denied before stage2: %s",
                      r->user, conf->realm, r->uri);
        make_stage1_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    } else {
        /* AUTH_GENERAL_ERROR (or worse)
         * We'll assume that the module has already said what its error
         * was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}


int authorize_stage2(request_rec *r, auth_pake_config_rec *conf, auth_pake_header_rec *resp) {
    authn_status       return_code;

    return_code = get_user_pake_info(r, r->user, conf);

    if (return_code != AUTH_USER_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: user `%s' in realm `%s' denied in stage 2: %s",
                      r->user, conf->realm, r->uri);
        make_stage1_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    }
     
    /* recv client X */
    EC_POINT *X = EC_POINT_new(conf->pake->public.G);
    if (!EC_POINT_hex2point(conf->pake->public.G, resp->hdr.X, X, conf->bn_ctx)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: couldn't convert hex X to EC_POINT: X=%s, uri=%s",
                      resp->hdr.X, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    pake_server_recv_X(conf->pake, X);

    /* compute expected respc */
    if (!pake_compute_respc(conf->pake, tcpcrypt_get_sid())) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: couldn't compute expected respc: uri=%s",
                      r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    char *exp_respc = conf->pake->shared.respc;
    char *client_respc = resp->hdr.respc;
    if (strcmp(exp_respc, client_respc)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_pake: user %s: respc mismatch: expected '%s', got '%s'",
                      r->user, exp_respc, client_respc);
        make_stage2_auth_challenge(r, conf, resp);
        return HTTP_UNAUTHORIZED;
    }

    resp->auth_ok = 1;

    return OK;
}

/*
 * Authorization-Info header code
 */

static int add_auth_info(request_rec *r)
{
    struct pake_http_header hdr;
    auth_pake_config_rec *conf =
        (auth_pake_config_rec *) ap_get_module_config(r->per_dir_config,
                                                          &auth_pake_module);
    auth_pake_header_rec *resp =
        (auth_pake_header_rec *) ap_get_module_config(r->request_config,
                                                          &auth_pake_module);
    char *ai, *resp_dig = NULL, *am = NULL;

    if (resp == NULL || !resp->needed_auth || conf == NULL || !resp->auth_ok) {
        return OK;
    }

    pake_compute_resps(conf->pake, tcpcrypt_get_sid());
    
    if (!conf->pake->shared.resps) {
        /* we failed to allocate a client struct */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* assemble Authentication-Info header
     */
    pake_http_header_clear(&hdr);
    hdr.type = PAKE_HTTP_AUTHENTICATION_INFO;
    strcpy(hdr.resps, conf->pake->shared.resps);
    ai = apr_palloc(r->pool, PAKE_HTTP_AUTHENTICATION_INFO_LENGTH);
    pake_http_header_stringify(ai, &hdr, 1);
    if (ai && ai[0]) {
        apr_table_mergen(r->headers_out, "Authentication-Info", ai);
    }

    return OK;
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

void make_stage1_auth_challenge(request_rec *r,
                         const auth_pake_config_rec *conf,
                         auth_pake_header_rec *resp)
{
    char *auth_header_line = NULL;

    pake_http_header_clear(&resp->hdr);
    resp->hdr.type = PAKE_HTTP_WWW_AUTHENTICATE_STAGE1;
    resp->hdr.realm = conf->realm;
    resp->hdr.username = NULL;

    auth_header_line = apr_palloc(r->pool, PAKE_HTTP_WWW_AUTHENTICATE_STAGE1_LENGTH(&resp->hdr));
    assert(pake_http_header_stringify(auth_header_line, &resp->hdr, 1));

    apr_table_mergen(r->err_headers_out, "WWW-Authenticate", auth_header_line);    
}

void make_stage2_auth_challenge(request_rec *r,
                         const auth_pake_config_rec *conf,
                         auth_pake_header_rec *resp)
{
    char *Yhex = NULL, *header_line = NULL;

    pake_http_header_clear(&resp->hdr);
    resp->hdr.type = PAKE_HTTP_WWW_AUTHENTICATE_STAGE2;
    resp->hdr.realm = conf->realm;

    assert(conf->pake->server_state.Y);
    Yhex = EC_POINT_point2hex(conf->pake->public.G, conf->pake->server_state.Y,
                              POINT_CONVERSION_UNCOMPRESSED, conf->bn_ctx);
    strcpy(resp->hdr.Y, Yhex);
    OPENSSL_free(Yhex);
    
    header_line = apr_palloc(r->pool, PAKE_HTTP_WWW_AUTHENTICATE_STAGE2_LENGTH(&resp->hdr));
    assert(pake_http_header_stringify(header_line, &resp->hdr, 1));
    apr_table_mergen(r->err_headers_out, "WWW-Authenticate", header_line);
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const cfgPost[]={ "http_core.c", NULL };

    ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(make_header_rec, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(authenticate_pake_user, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(add_auth_info, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_pake_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_pake_dir_config,   /* dir config creator */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    auth_pake_cmds,                /* command table */
    register_hooks              /* register hooks */
};

