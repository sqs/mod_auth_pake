#include "apache2_module_init.h"

#include <ctype.h>

/*
 * initialization code
 */

static apr_status_t initialize_secret(server_rec *s)
{
    apr_status_t status;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "auth_pake: generating secret for pake authentication ...");

#if APR_HAS_RANDOM
    status = apr_generate_random_bytes(auth_pake_secret, sizeof(auth_pake_secret));
#else
#error APR random number support is missing; you probably need to install the truerand library.
#endif

    if (status != APR_SUCCESS) {
        char buf[120];
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "auth_pake: error generating secret: %s",
                     apr_strerror(status, buf, sizeof(buf)));
        return status;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "auth_pake: done");

    return APR_SUCCESS;
}

int initialize_module(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "auth_pake_init";

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

    return OK;
}

/*
 * configuration code
 */

void *create_auth_pake_dir_config(apr_pool_t *p, char *dir)
{
    auth_pake_config_rec *conf;

    if (dir == NULL) {
        return NULL;
    }

    conf = (auth_pake_config_rec *) apr_pcalloc(p, sizeof(auth_pake_config_rec));
    if (conf) {
        conf->dir_name       = apr_pstrdup(p, dir);
    }

    return conf;
}

const char *set_realm(cmd_parms *cmd, void *config, const char *realm)
{
    int i;
    auth_pake_config_rec *conf = (auth_pake_config_rec *) config;

    /* Only allow [a-zA-Z0-9 _:/.] in realm. This means we don't have to escape
       the realm string on the server side. Of course, clients can send back a
       bad realm in the Authorization: header, but we can reject it instead of
       having to unescape it and/or reject it. */
    for (i = 0; i < strlen(realm); ++i) {
        char c = realm[i];
        if (!isalnum(c) && c != ' ' && c != '_' && c != ':' && c != '/' &&
            c != '.') {
            return apr_psprintf(cmd->pool, 
                                "Invalid AuthName '%s': must only contain [a-zA-Z0-9 _]",
                                realm);
        }
    }
    
    conf->realm = realm;

    return DECLINE_CMD;
}
