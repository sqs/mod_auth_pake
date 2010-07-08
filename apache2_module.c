#include "apache2_module.h"
#include "apache2_module_init.h"
#include "crypto.h"
#include "tcpcrypt_session.h"
#include <assert.h>

/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists */
static int get_digest_rec(request_rec *r, auth_tcpcrypt_header_rec *resp)
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


/* Get the request-uri (before any subrequests etc are initiated) and
 * initialize the request_config.
 */
static int parse_hdr(request_rec *r)
{
    auth_tcpcrypt_header_rec *resp;
    int res;

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    resp = apr_pcalloc(r->pool, sizeof(auth_tcpcrypt_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    resp->method = r->method;
    ap_set_module_config(r->request_config, &auth_tcpcrypt_module, resp);

    res = get_digest_rec(r, resp);
    //XXX resp->client = get_client(resp->opaque_num, r);

    return DECLINED;
}


/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

static void make_auth_challenge(request_rec *r,
                                const auth_tcpcrypt_config_rec *conf,
                                auth_tcpcrypt_header_rec *resp, int stale)
{
    char *h = malloc(1000); /* TODO */
    
    struct pake_info p;
    memset(&p, 0, sizeof(p));
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    assert(pake_server_init(&p, ctx));
  
    resp->hdr.type = HTTP_WWW_AUTHENTICATE;
    resp->hdr.realm = "protected area";

    char *s = EC_POINT_point2hex(p.public.G, p.server_state.Y,
                                 POINT_CONVERSION_UNCOMPRESSED, ctx);
    strcpy(resp->hdr.Y, s);
    OPENSSL_free(s);
    
    tcpcrypt_http_header_stringify(h, &resp->hdr, 1);
    apr_table_mergen(r->err_headers_out, "WWW-Authenticate", h);
}


/*
 * Authorization header verification code
 */

/* Gets pake info and stores it in `conf`. */
static authn_status get_user_pake_info(request_rec *r, const char *user,
                                       auth_tcpcrypt_config_rec *conf)
{
    authn_status auth_result;
    char *password;
    authn_provider_list *current_provider;

    current_provider = conf->providers;
    do {
        const authn_provider *provider;

        /* For now, if a provider isn't set, we'll be nice and use the file
         * provider.
         */
        if (!current_provider) {
            provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                          AUTHN_DEFAULT_PROVIDER, "0");

            if (!provider || !provider->get_realm_hash) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "No Authn provider configured");
                auth_result = AUTH_GENERAL_ERROR;
                break;
            }
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, AUTHN_DEFAULT_PROVIDER);
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
        }


        /* We expect the password to be md5 hash of user:realm:password */
        auth_result = provider->get_realm_hash(r, user, conf->realm,
                                               &password);

        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

        /* Something occured.  Stop checking. */
        if (auth_result != AUTH_USER_NOT_FOUND) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
           break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result == AUTH_USER_FOUND) {
        /* TODO2: get user pake info */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "AUTH_USER_FOUND for user: '%s'", user);
    }

    return auth_result;
}

static void copy_uri_components(apr_uri_t *dst,
                                apr_uri_t *src, request_rec *r) {
    if (src->scheme && src->scheme[0] != '\0') {
        dst->scheme = src->scheme;
    }
    else {
        dst->scheme = (char *) "http";
    }

    if (src->hostname && src->hostname[0] != '\0') {
        dst->hostname = apr_pstrdup(r->pool, src->hostname);
        ap_unescape_url(dst->hostname);
    }
    else {
        dst->hostname = (char *) ap_get_server_name(r);
    }

    if (src->port_str && src->port_str[0] != '\0') {
        dst->port = src->port;
    }
    else {
        dst->port = ap_get_server_port(r);
    }

    if (src->path && src->path[0] != '\0') {
        dst->path = apr_pstrdup(r->pool, src->path);
        ap_unescape_url(dst->path);
    }
    else {
        dst->path = src->path;
    }

    if (src->query && src->query[0] != '\0') {
        dst->query = apr_pstrdup(r->pool, src->query);
        ap_unescape_url(dst->query);
    }
    else {
        dst->query = src->query;
    }

    dst->hostinfo = src->hostinfo;
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if the attributes are correct, if it
 * really is that user, if the nonce is correct, etc.
 */

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
        /* XXX shouldn't print client input to log - remove this once it's fixed */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: need auth type %s, got %s", "Tcpcrypt", t);
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


    /* check for existence and syntax of Auth header */

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

    r->user         = (char *) resp->hdr.username;
    r->ap_auth_type = (char *) "Tcpcrypt";

    /* check the auth attributes */

    if (strcmp(resp->hdr.realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: realm mismatch - got `%s' but expected `%s'",
                      resp->hdr.realm, conf->realm);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    return_code = get_user_pake_info(r, r->user, conf);

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

    const char *exp_response;

    exp_response = get_userpw_hash(r, resp, conf);
    if (!exp_response) {
        /* we failed to allocate a client struct */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (0 /* TODO2 */) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user %s: password mismatch: %s", r->user,
                      r->uri);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    return OK;
}

/*
 * Authorization-Info header code
 */

static int add_auth_info(request_rec *r)
{
    const auth_tcpcrypt_config_rec *conf =
                (auth_tcpcrypt_config_rec *) ap_get_module_config(r->per_dir_config,
                                                           &auth_tcpcrypt_module);
    auth_tcpcrypt_header_rec *resp =
                (auth_tcpcrypt_header_rec *) ap_get_module_config(r->request_config,
                                                           &auth_tcpcrypt_module);
    const char *ai = NULL, *resp_dig = NULL;

    if (resp == NULL || !resp->needed_auth || conf == NULL) {
        return OK;
    }

    resp_dig = get_userpw_hash(r, resp, conf);
    if (!resp_dig) {
        /* we failed to allocate a client struct */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* assemble Authentication-Info header
     */
    ai = apr_pstrcat(r->pool,
                     "rspauth=\"", resp_dig, "\"",
                     NULL);

    if (ai && ai[0]) {
        apr_table_mergen(r->headers_out, "Authentication-Info", ai);
    }

    return OK;
}


static void register_hooks(apr_pool_t *p)
{
    static const char * const cfgPost[]={ "http_core.c", NULL };
    static const char * const parsePre[]={ "mod_proxy.c", NULL };

    ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(parse_hdr, parsePre, NULL, APR_HOOK_MIDDLE);
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

