/*
 * mod_auth_digest: MD5 digest authentication
 *
 * Originally by Alexei Kosut <akosut@nueva.pvt.k12.ca.us>
 * Updated to RFC-2617 by Ronald Tschalär <ronald@innovation.ch>
 * based on mod_auth, by Rob McCool and Robert S. Thau
 *
 * This module an updated version of modules/standard/mod_digest.c
 * It is still fairly new and problems may turn up - submit problem
 * reports to the Apache bug-database, or send them directly to me
 * at ronald@innovation.ch.
 *
 * Requires either /dev/random (or equivalent) or the truerand library,
 * available for instance from
 * ftp://research.att.com/dist/mab/librand.shar
 *
 * Open Issues:
 *   - qop=auth-int (when streams and trailer support available)
 *   - nonce-format configurability
 *   - Proxy-Authorization-Info header is set by this module, but is
 *     currently ignored by mod_proxy (needs patch to mod_proxy)
 *   - generating the secret takes a while (~ 8 seconds) if using the
 *     truerand library
 *   - The source of the secret should be run-time directive (with server
 *     scope: RSRC_CONF). However, that could be tricky when trying to
 *     choose truerand vs. file...
 *   - shared-mem not completely tested yet. Seems to work ok for me,
 *     but... (definitely won't work on Windoze)
 *   - Sharing a realm among multiple servers has following problems:
 *     o Server name and port can't be included in nonce-hash
 *       (we need two nonce formats, which must be configured explicitly)
 *     o Nonce-count check can't be for equal, or then nonce-count checking
 *       must be disabled. What we could do is the following:
 *       (expected < received) ? set expected = received : issue error
 *       The only problem is that it allows replay attacks when somebody
 *       captures a packet sent to one server and sends it to another
 *       one. Should we add "TcpcryptAuthNcCheck Strict"?
 *   - expired nonces give amaya fits.
 */

#include "apache2_module.h"
#include "crypto.h"
#include "tcpcrypt_session.h"


/* client list definitions */

static struct hash_table {
    client_entry  **table;
    unsigned long   tbl_len;
    unsigned long   num_entries;
    unsigned long   num_created;
    unsigned long   num_removed;
    unsigned long   num_renewed;
} *client_list;

/* (mostly) nonce stuff */

typedef union time_union {
    apr_time_t    time;
    unsigned char arr[sizeof(apr_time_t)];
} time_rec;

static unsigned char secret[SECRET_LEN];

/* client-list, opaque, and one-time-nonce stuff */

static apr_shm_t      *client_shm =  NULL;
static apr_rmm_t      *client_rmm = NULL;
static apr_time_t     *otn_counter;     /* one-time-nonce counter */
static apr_global_mutex_t *client_lock = NULL;
static char           client_lock_name[L_tmpnam];

#define DEF_SHMEM_SIZE  1000L           /* ~ 12 entries */
#define DEF_NUM_BUCKETS 15L
#define HASH_DEPTH      5

static long shmem_size  = DEF_SHMEM_SIZE;
static long num_buckets = DEF_NUM_BUCKETS;


module AP_MODULE_DECLARE_DATA auth_tcpcrypt_module;

/*
 * initialization code
 */

static apr_status_t cleanup_tables(void *not_used)
{
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                  "auth_tcpcrypt: cleaning up shared memory");
    fflush(stderr);

    if (client_shm) {
        apr_shm_destroy(client_shm);
        client_shm = NULL;
    }

    if (client_lock) {
        apr_global_mutex_destroy(client_lock);
        client_lock = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t initialize_secret(server_rec *s)
{
    apr_status_t status;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "auth_tcpcrypt: generating secret for tcpcrypt authentication ...");

#if APR_HAS_RANDOM
    status = apr_generate_random_bytes(secret, sizeof(secret));
#else
#error APR random number support is missing; you probably need to install the truerand library.
#endif

    if (status != APR_SUCCESS) {
        char buf[120];
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "auth_tcpcrypt: error generating secret: %s",
                     apr_strerror(status, buf, sizeof(buf)));
        return status;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "auth_tcpcrypt: done");

    return APR_SUCCESS;
}

static void log_error_and_cleanup(char *msg, apr_status_t sts, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, sts, s,
                 "auth_tcpcrypt: %s - all nonce-count checking and " \
                 "one-time nonces disabled", msg);

    cleanup_tables(NULL);
}

#if APR_HAS_SHARED_MEMORY

static void initialize_tables(server_rec *s, apr_pool_t *ctx)
{
    unsigned long idx;
    apr_status_t   sts;

    /* set up client list */

    sts = apr_shm_create(&client_shm, shmem_size, tmpnam(NULL), ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create shared memory segments", sts, s);
        return;
    }

    client_list = apr_rmm_malloc(client_rmm, sizeof(*client_list) +
                                            sizeof(client_entry*)*num_buckets);
    if (!client_list) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return;
    }
    client_list->table = (client_entry**) (client_list + 1);
    for (idx = 0; idx < num_buckets; idx++) {
        client_list->table[idx] = NULL;
    }
    client_list->tbl_len     = num_buckets;
    client_list->num_entries = 0;

    tmpnam(client_lock_name);
    /* FIXME: get the client_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_create(&client_lock, client_lock_name,
                                  APR_LOCK_DEFAULT, ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return;
    }

    /* setup one-time-nonce counter */

    otn_counter = apr_rmm_malloc(client_rmm, sizeof(*otn_counter));
    if (otn_counter == NULL) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return;
    }
    *otn_counter = 0;
    /* no lock here */


    /* success */
    return;
}

#endif /* APR_HAS_SHARED_MEMORY */


static int initialize_module(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "auth_digest_init";

    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK;
    }
    if (initialize_secret(s) != APR_SUCCESS) {
        return !OK;
    }

#if APR_HAS_SHARED_MEMORY
    /* Note: this stuff is currently fixed for the lifetime of the server,
     * i.e. even across restarts. This means that A) any shmem-size
     * configuration changes are ignored, and B) certain optimizations,
     * such as only allocating the smallest necessary entry for each
     * client, can't be done. However, the alternative is a nightmare:
     * we can't call apr_shm_destroy on a graceful restart because there
     * will be children using the tables, and we also don't know when the
     * last child dies. Therefore we can never clean up the old stuff,
     * creating a creeping memory leak.
     */
    initialize_tables(s, p);
    apr_pool_cleanup_register(p, NULL, cleanup_tables, apr_pool_cleanup_null);
#endif  /* APR_HAS_SHARED_MEMORY */
    return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t sts;

    if (!client_shm) {
        return;
    }

    /* FIXME: get the client_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_child_init(&client_lock, client_lock_name, p);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return;
    }
}

/*
 * configuration code
 */

static void *create_auth_tcpcrypt_dir_config(apr_pool_t *p, char *dir)
{
    auth_tcpcrypt_config_rec *conf;

    if (dir == NULL) {
        return NULL;
    }

    conf = (auth_tcpcrypt_config_rec *) apr_pcalloc(p, sizeof(auth_tcpcrypt_config_rec));
    if (conf) {
        conf->nonce_lifetime = DFLT_NONCE_LIFE;
        conf->dir_name       = apr_pstrdup(p, dir);
        conf->algorithm      = DFLT_ALGORITHM;
    }

    return conf;
}

static const char *set_realm(cmd_parms *cmd, void *config, const char *realm)
{
    auth_tcpcrypt_config_rec *conf = (auth_tcpcrypt_config_rec *) config;

    /* The core already handles the realm, but it's just too convenient to
     * grab it ourselves too and cache some setups. However, we need to
     * let the core get at it too, which is why we decline at the end -
     * this relies on the fact that http_core is last in the list.
     */
    conf->realm = realm;

    /* we precompute the part of the nonce hash that is constant (well,
     * the host:port would be too, but that varies for .htaccess files
     * and directives outside a virtual host section)
     */
    apr_sha1_init(&conf->nonce_ctx);
    apr_sha1_update_binary(&conf->nonce_ctx, secret, sizeof(secret));
    apr_sha1_update_binary(&conf->nonce_ctx, (const unsigned char *) realm,
                           strlen(realm));

    return DECLINE_CMD;
}

static const char *add_authn_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    auth_tcpcrypt_config_rec *conf = (auth_tcpcrypt_config_rec*)config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = apr_pstrdup(cmd->pool, arg);

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name, "0");

    if (newp->provider == NULL) {
       /* by the time they use it, the provider should be loaded and
           registered with us. */
        return apr_psprintf(cmd->pool,
                            "Unknown Authn provider: %s",
                            newp->provider_name);
    }

    if (!newp->provider->get_realm_hash) {
        /* if it doesn't provide the appropriate function, reject it */
        return apr_psprintf(cmd->pool,
                            "The '%s' Authn provider doesn't support "
                            "tcpcrypt Authentication", newp->provider_name);
    }

    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        authn_provider_list *last = conf->providers;

        while (last->next) {
            last = last->next;
        }
        last->next = newp;
    }

    return NULL;
}

static const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
                                      const char *t)
{
    char *endptr;
    long  lifetime;

    lifetime = strtol(t, &endptr, 10);
    if (endptr < (t+strlen(t)) && !apr_isspace(*endptr)) {
        return apr_pstrcat(cmd->pool,
                           "Invalid time in TcpcryptAuthNonceLifetime: ",
                           t, NULL);
    }

    ((auth_tcpcrypt_config_rec *) config)->nonce_lifetime = apr_time_from_sec(lifetime);
    return NULL;
}

static const char *set_nonce_format(cmd_parms *cmd, void *config,
                                    const char *fmt)
{
    ((auth_tcpcrypt_config_rec *) config)->nonce_format = fmt;
    return "TcpcryptAuthNonceFormat is not implemented (yet)";
}

static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
{
    if (strcasecmp(alg, "MD5")) {
        return apr_pstrcat(cmd->pool, "Invalid algorithm in TcpcryptAuthAlgorithm: ", alg, NULL);
    }

    ((auth_tcpcrypt_config_rec *) config)->algorithm = alg;
    return NULL;
}

static const char *set_uri_list(cmd_parms *cmd, void *config, const char *uri)
{
    auth_tcpcrypt_config_rec *c = (auth_tcpcrypt_config_rec *) config;
    if (c->uri_list) {
        c->uri_list[strlen(c->uri_list)-1] = '\0';
        c->uri_list = apr_pstrcat(cmd->pool, c->uri_list, " ", uri, "\"", NULL);
    }
    else {
        c->uri_list = apr_pstrcat(cmd->pool, ", domain=\"", uri, "\"", NULL);
    }
    return NULL;
}

static const char *set_shmem_size(cmd_parms *cmd, void *config,
                                  const char *size_str)
{
    char *endptr;
    long  size, min;

    size = strtol(size_str, &endptr, 10);
    while (apr_isspace(*endptr)) endptr++;
    if (*endptr == '\0' || *endptr == 'b' || *endptr == 'B') {
        ;
    }
    else if (*endptr == 'k' || *endptr == 'K') {
        size *= 1024;
    }
    else if (*endptr == 'm' || *endptr == 'M') {
        size *= 1048576;
    }
    else {
        return apr_pstrcat(cmd->pool, "Invalid size in TcpcryptAuthShmemSize: ",
                          size_str, NULL);
    }

    min = sizeof(*client_list) + sizeof(client_entry*) + sizeof(client_entry);
    if (size < min) {
        return apr_psprintf(cmd->pool, "size in TcpcryptAuthShmemSize too small: "
                           "%ld < %ld", size, min);
    }

    shmem_size  = size;
    num_buckets = (size - sizeof(*client_list)) /
                  (sizeof(client_entry*) + HASH_DEPTH * sizeof(client_entry));
    if (num_buckets == 0) {
        num_buckets = 1;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "auth_tcpcrypt: Set shmem-size: %ld, num-buckets: %ld", shmem_size,
                 num_buckets);

    return NULL;
}

static const command_rec auth_tcpcrypt_cmds[] =
{
    AP_INIT_TAKE1("AuthName", set_realm, NULL, OR_AUTHCFG,
     "The authentication realm (e.g. \"Members Only\")"),
    AP_INIT_ITERATE("TcpcryptAuthProvider", add_authn_provider, NULL, OR_AUTHCFG,
                     "specify the auth providers for a directory or location"),
    AP_INIT_TAKE1("TcpcryptAuthNonceLifetime", set_nonce_lifetime, NULL, OR_AUTHCFG,
     "Maximum lifetime of the server nonce (seconds)"),
    AP_INIT_TAKE1("TcpcryptAuthNonceFormat", set_nonce_format, NULL, OR_AUTHCFG,
     "The format to use when generating the server nonce"),
    AP_INIT_TAKE1("TcpcryptAuthAlgorithm", set_algorithm, NULL, OR_AUTHCFG,
     "The algorithm used for the hash calculation"),
    AP_INIT_ITERATE("TcpcryptAuthDomain", set_uri_list, NULL, OR_AUTHCFG,
     "A list of URI's which belong to the same protection space as the current URI"),
    AP_INIT_TAKE1("TcpcryptAuthShmemSize", set_shmem_size, NULL, RSRC_CONF,
     "The amount of shared memory to allocate for keeping track of clients"),
    {NULL}
};


/*
 * client list code
 *
 * Each client is assigned a number, which is transferred in the opaque
 * field of the WWW-Authenticate and Authorization headers. The number
 * is just a simple counter which is incremented for each new client.
 * Clients can't forge this number because it is hashed up into the
 * server nonce, and that is checked.
 *
 * The clients are kept in a simple hash table, which consists of an
 * array of client_entry's, each with a linked list of entries hanging
 * off it. The client's number modulo the size of the array gives the
 * bucket number.
 *
 * The clients are garbage collected whenever a new client is allocated
 * but there is not enough space left in the shared memory segment. A
 * simple semi-LRU is used for this: whenever a client entry is accessed
 * it is moved to the beginning of the linked list in its bucket (this
 * also makes for faster lookups for current clients). The garbage
 * collecter then just removes the oldest entry (i.e. the one at the
 * end of the list) in each bucket.
 *
 * The main advantages of the above scheme are that it's easy to implement
 * and it keeps the hash table evenly balanced (i.e. same number of entries
 * in each bucket). The major disadvantage is that you may be throwing
 * entries out which are in active use. This is not tragic, as these
 * clients will just be sent a new client id (opaque field) and nonce
 * with a stale=true (i.e. it will just look like the nonce expired,
 * thereby forcing an extra round trip). If the shared memory segment
 * has enough headroom over the current client set size then this should
 * not occur too often.
 *
 * To help tune the size of the shared memory segment (and see if the
 * above algorithm is really sufficient) a set of counters is kept
 * indicating the number of clients held, the number of garbage collected
 * clients, and the number of erroneously purged clients. These are printed
 * out at each garbage collection run. Note that access to the counters is
 * not synchronized because they are just indicaters, and whether they are
 * off by a few doesn't matter; and for the same reason no attempt is made
 * to guarantee the num_renewed is correct in the face of clients spoofing
 * the opaque field.
 */

/*
 * Get the client given its client number (the key). Returns the entry,
 * or NULL if it's not found.
 *
 * Access to the list itself is synchronized via locks. However, access
 * to the entry returned by get_client() is NOT synchronized. This means
 * that there are potentially problems if a client uses multiple,
 * simultaneous connections to access url's within the same protection
 * space. However, these problems are not new: when using multiple
 * connections you have no guarantee of the order the requests are
 * processed anyway, so you have problems with the nonce-count and
 * one-time nonces anyway.
 */
static client_entry *get_client(unsigned long key, const request_rec *r)
{
    int bucket;
    client_entry *entry, *prev = NULL;


    if (!key || !client_shm)  return NULL;

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    apr_global_mutex_lock(client_lock);

    while (entry && key != entry->key) {
        prev  = entry;
        entry = entry->next;
    }

    if (entry && prev) {                /* move entry to front of list */
        prev->next  = entry->next;
        entry->next = client_list->table[bucket];
        client_list->table[bucket] = entry;
    }

    apr_global_mutex_unlock(client_lock);

    if (entry) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "get_client(): client %lu found", key);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "get_client(): client %lu not found", key);
    }

    return entry;
}


/* A simple garbage-collecter to remove unused clients. It removes the
 * last entry in each bucket and updates the counters. Returns the
 * number of removed entries.
 */
static long gc(void)
{
    client_entry *entry, *prev;
    unsigned long num_removed = 0, idx;

    /* garbage collect all last entries */

    for (idx = 0; idx < client_list->tbl_len; idx++) {
        entry = client_list->table[idx];
        prev  = NULL;
        while (entry->next) {   /* find last entry */
            prev  = entry;
            entry = entry->next;
        }
        if (prev) {
            prev->next = NULL;   /* cut list */
        }
        else {
            client_list->table[idx] = NULL;
        }
        if (entry) {                    /* remove entry */
            apr_rmm_free(client_rmm, (apr_rmm_off_t)entry);
            num_removed++;
        }
    }

    /* update counters and log */

    client_list->num_entries -= num_removed;
    client_list->num_removed += num_removed;

    return num_removed;
}


/*
 * Add a new client to the list. Returns the entry if successful, NULL
 * otherwise. This triggers the garbage collection if memory is low.
 */
static client_entry *add_client(unsigned long key, client_entry *info,
                                server_rec *s)
{
    int bucket;
    client_entry *entry;


    if (!key || !client_shm) {
        return NULL;
    }

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    apr_global_mutex_lock(client_lock);

    /* try to allocate a new entry */

    entry = (client_entry *)apr_rmm_malloc(client_rmm, sizeof(client_entry));
    if (!entry) {
        long num_removed = gc();
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "auth_tcpcrypt: gc'd %ld client entries. Total new clients: "
                     "%ld; Total removed clients: %ld; Total renewed clients: "
                     "%ld", num_removed,
                     client_list->num_created - client_list->num_renewed,
                     client_list->num_removed, client_list->num_renewed);
        entry = (client_entry *)apr_rmm_malloc(client_rmm, sizeof(client_entry));
        if (!entry) {
            return NULL;       /* give up */
        }
    }

    /* now add the entry */

    memcpy(entry, info, sizeof(client_entry));
    entry->key  = key;
    entry->next = client_list->table[bucket];
    client_list->table[bucket] = entry;
    client_list->num_created++;
    client_list->num_entries++;

    apr_global_mutex_unlock(client_lock);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "allocated new client %lu", key);

    return entry;
}


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

    auth_line = apr_table_get(r->headers_in,
                             (PROXYREQ_PROXY == r->proxyreq)
                                 ? "Proxy-Authorization"
                                 : "Authorization");
    if (!auth_line) {
        resp->auth_hdr_sts = NO_HEADER;
        return !OK;
    }

    resp->scheme = ap_getword_white(r->pool, &auth_line);
    if (strcasecmp(resp->scheme, "Tcpcrypt")) {
        resp->auth_hdr_sts = NOT_TCPCRYPT_AUTH;
        return !OK;
    }

    l = strlen(auth_line);

    key   = apr_palloc(r->pool, l+1);
    value = apr_palloc(r->pool, l+1);

    while (auth_line[0] != '\0') {

        /* find key */

        while (apr_isspace(auth_line[0])) {
            auth_line++;
        }
        vk = 0;
        while (auth_line[0] != '=' && auth_line[0] != ','
               && auth_line[0] != '\0' && !apr_isspace(auth_line[0])) {
            key[vk++] = *auth_line++;
        }
        key[vk] = '\0';
        while (apr_isspace(auth_line[0])) {
            auth_line++;
        }

        /* find value */

        if (auth_line[0] == '=') {
            auth_line++;
            while (apr_isspace(auth_line[0])) {
                auth_line++;
            }

            vv = 0;
            if (auth_line[0] == '\"') {         /* quoted string */
                auth_line++;
                while (auth_line[0] != '\"' && auth_line[0] != '\0') {
                    if (auth_line[0] == '\\' && auth_line[1] != '\0') {
                        auth_line++;            /* escaped char */
                    }
                    value[vv++] = *auth_line++;
                }
                if (auth_line[0] != '\0') {
                    auth_line++;
                }
            }
            else {                               /* token */
                while (auth_line[0] != ',' && auth_line[0] != '\0'
                       && !apr_isspace(auth_line[0])) {
                    value[vv++] = *auth_line++;
                }
            }
            value[vv] = '\0';
        }

        while (auth_line[0] != ',' && auth_line[0] != '\0') {
            auth_line++;
        }
        if (auth_line[0] != '\0') {
            auth_line++;
        }

        if (!strcasecmp(key, "username"))
            resp->username = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "realm"))
            resp->realm = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "nonce"))
            resp->nonce = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "uri"))
            resp->uri = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "response"))
            resp->digest = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "algorithm"))
            resp->algorithm = apr_pstrdup(r->pool, value);
    }

    if (!resp->username || !resp->realm || !resp->nonce || !resp->uri
        || !resp->digest) {
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
static void gen_nonce_hash(char *hash, const char *timestr, const char *opaque,
                           const server_rec *server,
                           const auth_tcpcrypt_config_rec *conf)
{
    const char *hex = "0123456789abcdef";
    unsigned char sha1[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t ctx;
    int idx;

    memcpy(&ctx, &conf->nonce_ctx, sizeof(ctx));
    /*
    apr_sha1_update_binary(&ctx, (const unsigned char *) server->server_hostname,
                         strlen(server->server_hostname));
    apr_sha1_update_binary(&ctx, (const unsigned char *) &server->port,
                         sizeof(server->port));
     */
    apr_sha1_update_binary(&ctx, (const unsigned char *) timestr, strlen(timestr));
    if (opaque) {
        apr_sha1_update_binary(&ctx, (const unsigned char *) opaque,
                             strlen(opaque));
    }
    apr_sha1_final(sha1, &ctx);

    for (idx=0; idx<APR_SHA1_DIGESTSIZE; idx++) {
        *hash++ = hex[sha1[idx] >> 4];
        *hash++ = hex[sha1[idx] & 0xF];
    }

    *hash++ = '\0';
}


/* The nonce has the format b64(time)+hash .
 */
static const char *gen_nonce(apr_pool_t *p, apr_time_t now, const char *opaque,
                             const server_rec *server,
                             const auth_tcpcrypt_config_rec *conf)
{
    char *nonce = apr_palloc(p, NONCE_LEN+1);
    int len;
    time_rec t;

    if (conf->nonce_lifetime != 0) {
        t.time = now;
    }
    else if (otn_counter) {
        /* this counter is not synch'd, because it doesn't really matter
         * if it counts exactly.
         */
        t.time = (*otn_counter)++;
    }
    else {
        /* XXX: WHAT IS THIS CONSTANT? */
        t.time = 42;
    }
    len = apr_base64_encode_binary(nonce, t.arr, sizeof(t.arr));
    gen_nonce_hash(nonce+NONCE_TIME_LEN, nonce, opaque, server, conf);

    return nonce;
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

static void note_digest_auth_failure(request_rec *r,
                                     const auth_tcpcrypt_config_rec *conf,
                                     auth_tcpcrypt_header_rec *resp, int stale)
{
    const char   *qop, *opaque, *opaque_param, *domain, *nonce;
    int           cnt;

    /* Setup nonce */

    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf);
    if (resp->client && conf->nonce_lifetime == 0) {
        memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
    }

    /* setup domain attribute. We want to send this attribute wherever
     * possible so that the client won't send the Authorization header
     * unneccessarily (it's usually > 200 bytes!).
     */


    /* don't send domain
     * - if it's not specified
     */
    if (!conf->uri_list) {
        domain = NULL;
    }
    else {
        domain = conf->uri_list;
    }

    apr_table_mergen(r->err_headers_out,
                     "WWW-Authenticate",
                     apr_psprintf(r->pool, "Tcpcrypt realm=\"%s\", "
                                  "nonce=\"%s\", algorithm=%s%s%s%s",
                                  ap_auth_name(r), nonce, conf->algorithm,
                                  domain ? domain : "",
                                  stale ? ", stale=true" : "", qop));

}


/*
 * Authorization header verification code
 */

static authn_status get_hash(request_rec *r, const char *user,
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
        conf->ha1 = password;
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
                          "`%s': %s", resp->scheme, r->uri);
        }
        else if (resp->auth_hdr_sts == INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "auth_tcpcrypt: missing user, realm, nonce, uri, or digest"
                          " in authorization header: %s",
                          r->uri);
        }
        /* else (resp->auth_hdr_sts == NO_HEADER) */
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    r->user         = (char *) resp->username;
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

    /* XXX add back */
    /* if (resp->opaque && resp->opaque_num == 0) { */
    /*     ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
    /*                   "auth_tcpcrypt: received invalid opaque - got `%s'", */
    /*                   resp->opaque); */
    /*     note_digest_auth_failure(r, conf, resp, 0); */
    /*     return HTTP_UNAUTHORIZED; */
    /*} */

    if (strcmp(resp->realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: realm mismatch - got `%s' but expected `%s'",
                      resp->realm, conf->realm);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    if (resp->algorithm != NULL
        && strcasecmp(resp->algorithm, "MD5")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: unknown algorithm `%s' received: %s",
                      resp->algorithm, r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    return_code = get_hash(r, r->user, conf);

    if (return_code == AUTH_USER_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user `%s' in realm `%s' not found: %s",
                      r->user, conf->realm, r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
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
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }
    else {
        /* AUTH_GENERAL_ERROR (or worse)
         * We'll assume that the module has already said what its error
         * was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    const char *exp_digest;

    exp_digest = get_userpw_hash(r, resp, conf);
    if (!exp_digest) {
        /* we failed to allocate a client struct */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (strcmp(resp->digest, exp_digest)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "auth_tcpcrypt: user %s: password mismatch: %s", r->user,
                      r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    /* Note: this check is done last so that a "stale=true" can be
       generated if the nonce is old */
    if ((res = check_nonce(r, resp, conf))) {
        return res;
    }

    return OK;
}

/*
 * Authorization-Info header code
 */

#ifdef SEND_DIGEST
static const char *hdr(const apr_table_t *tbl, const char *name)
{
    const char *val = apr_table_get(tbl, name);
    if (val) {
        return val;
    }
    else {
        return "";
    }
}
#endif

static int add_auth_info(request_rec *r)
{
    const auth_tcpcrypt_config_rec *conf =
                (auth_tcpcrypt_config_rec *) ap_get_module_config(r->per_dir_config,
                                                           &auth_tcpcrypt_module);
    auth_tcpcrypt_header_rec *resp =
                (auth_tcpcrypt_header_rec *) ap_get_module_config(r->request_config,
                                                           &auth_tcpcrypt_module);
    const char *ai = NULL, *digest = NULL, *nextnonce = "";

    if (resp == NULL || !resp->needed_auth || conf == NULL) {
        return OK;
    }

    const char *resp_dig, *ha1, *a2, *ha2;

    ha1 = conf->ha1;

    a2 = apr_pstrcat(r->pool, ":", resp->uri, NULL);
    ha2 = ap_md5(r->pool, (const unsigned char *)a2);

    resp_dig = ap_md5(r->pool,
                      (unsigned char *)apr_pstrcat(r->pool, ha1, ":",
                                                   resp->nonce, ":",
                                                   ":", ha2, NULL));

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

