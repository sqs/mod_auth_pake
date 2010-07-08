#include "apache2_module_init.h"

#include <ctype.h>


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
        conf->dir_name       = apr_pstrdup(p, dir);
    }

    return conf;
}

const char *set_realm(cmd_parms *cmd, void *config, const char *realm)
{
    int i;
    auth_tcpcrypt_config_rec *conf = (auth_tcpcrypt_config_rec *) config;

    /* Only allow [a-zA-Z0-9 _] in realm. This means we don't have to escape
       the realm string on the server side. Of course, clients can send back a
       bad realm in the Authorization: header, but we can reject it instead of
       having to unescape it and/or reject it. */
    for (i = 0; i < strlen(realm); ++i) {
        char c = realm[i];
        if (!isalnum(c) && c != ' ' && c != '_') {
            return apr_psprintf(cmd->pool, 
                                "Invalid AuthName '%s': must only contain [a-zA-Z0-9 _]",
                                realm);
        }
    }
    
    conf->realm = realm;

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

