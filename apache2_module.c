#include "apache2_module.h"
#include "apache2_module_init.h"
#include "crypto.h"
#include "tcpcrypt_session.h"
#include <assert.h>
int parse_authorization_header(request_rec *r, auth_tcpcrypt_header_rec *resp);
void make_auth_challenge(request_rec *r,
                         const auth_tcpcrypt_config_rec *conf,
                         auth_tcpcrypt_header_rec *resp, int stale);

/* Get the request-uri (before any subrequests etc are initiated) and
 * initialize the request_config.
 */
static int make_header_rec(request_rec *r)
{
    auth_tcpcrypt_header_rec *resp;

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    resp = apr_pcalloc(r->pool, sizeof(auth_tcpcrypt_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    resp->auth_ok = 0;
    resp->method = r->method;
    ap_set_module_config(r->request_config, &auth_tcpcrypt_module, resp);

    parse_authorization_header(r, resp);

    return DECLINED;
}



/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists */
int parse_authorization_header(request_rec *r, auth_tcpcrypt_header_rec *resp)
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

    tcpcrypt_http_header_parse(&resp->hdr, auth_line, HTTP_AUTHORIZATION);
    
    if (!resp->hdr.auth_name || strcasecmp(resp->hdr.auth_name, "Tcpcrypt")) {
        resp->auth_hdr_sts = NOT_TCPCRYPT_AUTH;
        return !OK;
    }

    if (!resp->hdr.username || !resp->hdr.realm || !resp->hdr.X || !resp->hdr.respc) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing field in Authorization header: '%s'", auth_line);
        

        resp->auth_hdr_sts = INVALID;
        return !OK;
    }

    resp->auth_hdr_sts = VALID;
    return OK;
}





/*
 * Authorization header verification code
 */

/* Gets pake auth info for `user` (pi_0, pi_1, username) and stores it in `conf`. */
static authn_status get_user_pake_info(request_rec *r, const char *username,
                                       auth_tcpcrypt_config_rec *conf)
{
    authn_status authn_result;
    
    struct pake_info *pake = &conf->pake;
    memset(pake, 0, sizeof(*pake));
    conf->bn_ctx = BN_CTX_new();
    BN_CTX_start(conf->bn_ctx);
    assert(pake_server_init(pake, conf->bn_ctx));  
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "--------------- get_user_pake_info");

    /* TODO: obviously un-hardcode */
    if (username && username[0] != '\0' && strcmp(username, "jsmith") == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "--------------- username");

        BIGNUM *pi_0;
        assert(BN_hex2bn(&pi_0, "CBCE5FA4832FFFDF6D5A2F249BD0B89DBB1CD98908564BC2908B5109BA546FBC"));
        assert(conf->pake.public.G);
        EC_POINT *L = EC_POINT_new(conf->pake.public.G);
        EC_POINT_hex2point(conf->pake.public.G, "04888D011AFDEFD6B336A96D4CC3052A842527B0134A6F7AAB11CF62A3276C526CCBF8F8EEF55C61CCD22F8578693D1CC9811DE95C04D9A0D73EC9B00F99E939DF", L, conf->bn_ctx);
        assert(L);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "L = %s, pi_0 = %s", EC_POINT_point2hex(conf->pake.public.G, L, POINT_CONVERSION_UNCOMPRESSED, conf->bn_ctx), BN_bn2hex(pi_0));

        assert(pake_server_set_credentials(&conf->pake, "jsmith", "protected area", pi_0, L, conf->bn_ctx));
        /* TODO: in pake.c, this is currently also hardcoded -- change it there, too */
        authn_result = AUTH_USER_FOUND;
    } else {
        authn_result = AUTH_USER_NOT_FOUND;
    }

    return authn_result;
}


/* Determine user ID, and check if the attributes are correct. */

static int authenticate_tcpcrypt_user(request_rec *r)
{
    auth_tcpcrypt_config_rec *conf;
    auth_tcpcrypt_header_rec *resp;
    request_rec       *mainreq;
    const char        *t;
    int                res;
    authn_status       return_code;

    /* do we require Tcpcrypt auth for this URI? */

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Tcpcrypt")) {
        return DECLINED;
    }

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: need AuthName: %s", r->uri);
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
    resp = (auth_tcpcrypt_header_rec *) ap_get_module_config(mainreq->request_config,
                                                      &auth_tcpcrypt_module);
    resp->needed_auth = 1;

    /* get our conf */

    conf = (auth_tcpcrypt_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &auth_tcpcrypt_module);

    r->user         = (char *) resp->hdr.username;
    r->ap_auth_type = (char *) "Tcpcrypt";
    return_code = get_user_pake_info(r, r->user, conf);

    /* check for existence and syntax of Authorization header */

    if (resp->auth_hdr_sts != VALID) {
        if (resp->auth_hdr_sts == NOT_TCPCRYPT_AUTH) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_tcpcrypt: client used wrong authentication scheme "
                          "`%s': %s", resp->hdr.auth_name, r->uri);
        }
        else if (resp->auth_hdr_sts == INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_tcpcrypt: missing user, realm, nonce, uri, or digest"
                          " in authorization header: %s",
                          r->uri);
        }
        /* else (resp->auth_hdr_sts == NO_HEADER) */
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    /* check the auth attributes */

    if (strcmp(resp->hdr.realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: realm mismatch - got `%s' but expected `%s'",
                      resp->hdr.realm, conf->realm);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    if (return_code == AUTH_USER_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user `%s' in realm `%s' not found: %s",
                      r->user, conf->realm, r->uri);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }
    else if (return_code == AUTH_USER_FOUND) {
        /* we have a password, so continue */
    }
    else if (return_code == AUTH_DENIED) {
        /* authentication denied in the provider before attempting a match */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user `%s' in realm `%s' denied by provider: %s",
                      r->user, conf->realm, r->uri);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }
    else {
        /* AUTH_GENERAL_ERROR (or worse)
         * We'll assume that the module has already said what its error
         * was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* recv client X */
    EC_POINT *X = EC_POINT_new(conf->pake.public.G);
    assert(EC_POINT_hex2point(conf->pake.public.G, resp->hdr.X, X, conf->bn_ctx));
    pake_server_recv_X(&conf->pake, X);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "------- X = %s", resp->hdr.X);

    if (!tcpcrypt_pake_compute_respc(&conf->pake, tcpcrypt_get_sid(), conf->bn_ctx)) {
        /* failed to compute respc */
        assert(0);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "-------");    
    char *exp_respc = conf->pake.shared.respc;
    char *client_respc = resp->hdr.respc;
    if (strcmp(exp_respc, client_respc)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user %s: respc mismatch: expected '%s', got '%s'",
                      r->user, exp_respc, client_respc);
        make_auth_challenge(r, conf, resp, 0);
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
    struct tcpcrypt_http_header hdr;
    auth_tcpcrypt_config_rec *conf =
        (auth_tcpcrypt_config_rec *) ap_get_module_config(r->per_dir_config,
                                                          &auth_tcpcrypt_module);
    auth_tcpcrypt_header_rec *resp =
        (auth_tcpcrypt_header_rec *) ap_get_module_config(r->request_config,
                                                          &auth_tcpcrypt_module);
    char *ai, *resp_dig = NULL;

    if (resp == NULL || !resp->needed_auth || conf == NULL || !resp->auth_ok) {
        return OK;
    }

    tcpcrypt_pake_compute_resps(&conf->pake, tcpcrypt_get_sid(), conf->bn_ctx);
    
    if (!conf->pake.shared.resps) {
        /* we failed to allocate a client struct */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* assemble Authentication-Info header
     */
    hdr.type = HTTP_AUTHENTICATION_INFO;
    strcpy(hdr.resps, conf->pake.shared.resps);
    ai = apr_palloc(r->pool, TCPCRYPT_HTTP_AUTHENTICATION_INFO_LENGTH);
    tcpcrypt_http_header_stringify(ai, &hdr, 1);
    if (ai && ai[0]) {
        apr_table_mergen(r->headers_out, "Authentication-Info", ai);
    }

    return OK;
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

void make_auth_challenge(request_rec *r,
                         const auth_tcpcrypt_config_rec *conf,
                         auth_tcpcrypt_header_rec *resp, int stale)
{
    char *Yhex = NULL, *header_line = NULL;
    BN_CTX *ctx = NULL;
  
    resp->hdr.type = HTTP_WWW_AUTHENTICATE;
    resp->hdr.realm = conf->realm;
    
    assert(conf->pake.server_state.Y);
    Yhex = EC_POINT_point2hex(conf->pake.public.G, conf->pake.server_state.Y,
                              POINT_CONVERSION_UNCOMPRESSED, ctx);
    strcpy(resp->hdr.Y, Yhex);
    OPENSSL_free(Yhex);
    
    header_line = apr_palloc(r->pool, TCPCRYPT_HTTP_WWW_AUTHENTICATE_LENGTH(&resp->hdr));
    tcpcrypt_http_header_stringify(header_line, &resp->hdr, 1);
    apr_table_mergen(r->err_headers_out, "WWW-Authenticate", header_line);
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const cfgPost[]={ "http_core.c", NULL };
    static const char * const parsePre[]={ "mod_proxy.c", NULL };

    ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(make_header_rec, parsePre, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(authenticate_tcpcrypt_user, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(add_auth_info, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_tcpcrypt_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_tcpcrypt_dir_config,   /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    auth_tcpcrypt_cmds,                /* command table */
    register_hooks              /* register hooks */
};

