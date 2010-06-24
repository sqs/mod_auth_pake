#include "apache2_module_init.h"


/* client-list, opaque, and one-time-nonce stuff */

#define DEF_SHMEM_SIZE  1000L           /* ~ 12 entries */
#define DEF_NUM_BUCKETS 15L
#define HASH_DEPTH      5

static long shmem_size  = DEF_SHMEM_SIZE;
static long num_buckets = DEF_NUM_BUCKETS;

/* client list definitions */

static struct hash_table {
    client_entry  **table;
    unsigned long   tbl_len;
    unsigned long   num_entries;
    unsigned long   num_created;
    unsigned long   num_removed;
    unsigned long   num_renewed;
} *client_list;


static unsigned char secret[SECRET_LEN];


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


int initialize_module(apr_pool_t *p, apr_pool_t *plog,
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

void initialize_child(apr_pool_t *p, server_rec *s)
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

void *create_auth_tcpcrypt_dir_config(apr_pool_t *p, char *dir)
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

const char *set_realm(cmd_parms *cmd, void *config, const char *realm)
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

const char *add_authn_provider(cmd_parms *cmd, void *config,
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

const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
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

const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
{
    if (strcasecmp(alg, "MD5")) {
        return apr_pstrcat(cmd->pool, "Invalid algorithm in TcpcryptAuthAlgorithm: ", alg, NULL);
    }

    ((auth_tcpcrypt_config_rec *) config)->algorithm = alg;
    return NULL;
}

const char *set_uri_list(cmd_parms *cmd, void *config, const char *uri)
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

const char *set_shmem_size(cmd_parms *cmd, void *config,
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

