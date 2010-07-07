#include "apache2_module.h"
#include "apache2_module_init.h"
#include "crypto.h"
#include "tcpcrypt_session.h"

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

    resp->hdr.auth_name = ap_getword_white(r->pool, &auth_line);
    if (strcasecmp(resp->hdr.auth_name, "Tcpcrypt")) {
        resp->auth_hdr_sts = NOT_TCPCRYPT_AUTH;
        return !OK;
    }

    tcpcrypt_http_header_parse(&resp->hdr, auth_line, HTTP_AUTHORIZATION);

    if (!resp->hdr.username || !resp->hdr.realm || !resp->hdr.X || !resp->hdr.respc) {
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
 * Nonce generation code
 */

/* The hash part of the nonce is a SHA-1 hash of the time, realm, server host
 * and port, opaque, and our secret.
 */
static void gen_nonce_hash(char *hash, const char *timestr,
                           const server_rec *server,
                           const auth_tcpcrypt_config_rec *conf)
{
    const char *hex = "0123456789abcdef";
    unsigned char sha1[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t ctx;
    int idx;


    /*
    apr_sha1_update_binary(&ctx, (const unsigned char *) server->server_hostname,
                         strlen(server->server_hostname));
    apr_sha1_update_binary(&ctx, (const unsigned char *) &server->port,
                         sizeof(server->port));
     */
    /* apr_sha1_update_binary(&ctx, (const unsigned char *) timestr, strlen(timestr)); */
    /* apr_sha1_final(sha1, &ctx); */

    /* for (idx=0; idx<APR_SHA1_DIGESTSIZE; idx++) { */
    /*     *hash++ = hex[sha1[idx] >> 4]; */
    /*     *hash++ = hex[sha1[idx] & 0xF]; */
    /* } */

    /* *hash++ = '\0'; */
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

static void make_auth_challenge(request_rec *r,
                                const auth_tcpcrypt_config_rec *conf,
                                auth_tcpcrypt_header_rec *resp, int stale)
{
    char *h = malloc(1000); /* TODO */
    
    resp->hdr.type = HTTP_WWW_AUTHENTICATE;
    resp->hdr.realm = "protected area";
    resp->hdr.Y = "asdf";
    
    tcpcrypt_http_header_stringify(h, &resp->hdr, 1);
    apr_table_mergen(r->err_headers_out, "WWW-Authenticate", h);
}


/*
 * Authorization header verification code
 */

/* Gets HA1 and stores it in `conf`. */
static authn_status get_ha1(request_rec *r, const char *user,
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
        /*conf->ha1 = password;*/
        /* TODO2 */
    }

    return auth_result;
}

static int check_nonce(request_rec *r, auth_tcpcrypt_header_rec *resp,
                       const auth_tcpcrypt_config_rec *conf)
{
    return OK;
    /* apr_time_t dt; */
    /* int len; */
    /* time_rec nonce_time; */
    /* char tmp, hash[NONCE_HASH_LEN+1]; */

    /* if (strlen(resp->nonce) != NONCE_LEN) { */
    /*     ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
    /*                   "auth_tcpcrypt: invalid nonce %s received - length is not %d", */
    /*                   resp->nonce, NONCE_LEN); */
    /*     note_digest_auth_failure(r, conf, resp, 1); */
    /*     return HTTP_UNAUTHORIZED; */
    /* } */

    /* tmp = resp->nonce[NONCE_TIME_LEN]; */
    /* resp->nonce[NONCE_TIME_LEN] = '\0'; */
    /* len = apr_base64_decode_binary(nonce_time.arr, resp->nonce); */
    /* gen_nonce_hash(hash, resp->nonce, resp->opaque, r->server, conf); */
    /* resp->nonce[NONCE_TIME_LEN] = tmp; */
    /* resp->nonce_time = nonce_time.time; */

    /* if (strcmp(hash, resp->nonce+NONCE_TIME_LEN)) { */
    /*     ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
    /*                   "auth_tcpcrypt: invalid nonce %s received - hash is not %s", */
    /*                   resp->nonce, hash); */
    /*     note_digest_auth_failure(r, conf, resp, 1); */
    /*     return HTTP_UNAUTHORIZED; */
    /* } */

    /* return OK; */
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

    /* do we require Digest auth for this URI? */

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

    if (strcmp(resp->uri, resp->raw_request_uri)) {
        /* Hmm, the simple match didn't work (probably a proxy modified the
         * request-uri), so lets do a more sophisticated match
         */
        apr_uri_t r_uri, d_uri;

        copy_uri_components(&r_uri, resp->psd_request_uri, r);
        if (apr_uri_parse(r->pool, resp->uri, &d_uri) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_tcpcrypt: invalid uri <%s> in Authorization header",
                          resp->uri);
            return HTTP_BAD_REQUEST;
        }

        if (d_uri.hostname) {
            ap_unescape_url(d_uri.hostname);
        }
        if (d_uri.path) {
            ap_unescape_url(d_uri.path);
        }

        if (d_uri.query) {
            ap_unescape_url(d_uri.query);
        }

        if (r->method_number == M_CONNECT) {
            if (!r_uri.hostinfo || strcmp(resp->uri, r_uri.hostinfo)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "auth_tcpcrypt: uri mismatch - <%s> does not match "
                              "request-uri <%s>", resp->uri, r_uri.hostinfo);
                return HTTP_BAD_REQUEST;
            }
        }
        else if (
            /* check hostname matches, if present */
            (d_uri.hostname && d_uri.hostname[0] != '\0'
              && strcasecmp(d_uri.hostname, r_uri.hostname))
            /* check port matches, if present */
            || (d_uri.port_str && d_uri.port != r_uri.port)
            /* check that server-port is default port if no port present */
            || (d_uri.hostname && d_uri.hostname[0] != '\0'
                && !d_uri.port_str && r_uri.port != ap_default_port(r))
            /* check that path matches */
            || (d_uri.path != r_uri.path
                /* either exact match */
                && (!d_uri.path || !r_uri.path
                    || strcmp(d_uri.path, r_uri.path))
                /* or '*' matches empty path in scheme://host */
                && !(d_uri.path && !r_uri.path && resp->psd_request_uri->hostname
                    && d_uri.path[0] == '*' && d_uri.path[1] == '\0'))
            /* check that query matches */
            || (d_uri.query != r_uri.query
                && (!d_uri.query || !r_uri.query
                    || strcmp(d_uri.query, r_uri.query)))
            ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_tcpcrypt: uri mismatch - <%s> does not match "
                          "request-uri <%s>", resp->uri, resp->raw_request_uri);
            return HTTP_BAD_REQUEST;
        }
    }

    if (strcmp(resp->hdr.realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: realm mismatch - got `%s' but expected `%s'",
                      resp->hdr.realm, conf->realm);
        make_auth_challenge(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    return_code = get_ha1(r, r->user, conf);

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
    if (/* correct respc */0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user %s: password mismatch: %s", r->user,
                      r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
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

