#ifndef MOD_AUTH_TCPCRYPT_APACHE2_MODULE_INIT_H
#define MOD_AUTH_TCPCRYPT_APACHE2_MODULE_INIT_H

#include <httpd.h>
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "apr_uri.h"
#include "util_md5.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "ap_provider.h"

#include "mod_auth.h"

#include "apache2_module.h"
#include "pake.h"


static apr_shm_t      *client_shm =  NULL;
static apr_rmm_t      *client_rmm = NULL;
apr_time_t     *otn_counter;     /* one-time-nonce counter */
static apr_global_mutex_t *client_lock = NULL;
char            client_lock_name[L_tmpnam];

module AP_MODULE_DECLARE_DATA auth_tcpcrypt_module;


int initialize_module(apr_pool_t *p, apr_pool_t *plog,
                      apr_pool_t *ptemp, server_rec *s);
void initialize_child(apr_pool_t *p, server_rec *s);
void *create_auth_tcpcrypt_dir_config(apr_pool_t *p, char *dir);

const char *set_realm(cmd_parms *cmd, void *config, const char *realm);

/* struct to hold the configuration info */

typedef struct auth_tcpcrypt_config_struct {
    const char  *dir_name;
    authn_provider_list *providers;
    const char  *realm;
    const char *pakefile;
    BN_CTX      *bn_ctx;
    struct pake_info pake;
} auth_tcpcrypt_config_rec;


static const command_rec auth_tcpcrypt_cmds[] =
{
    AP_INIT_TAKE1("AuthName", set_realm, NULL, OR_AUTHCFG,
     "The authentication realm (e.g. \"Members Only\")"),
    AP_INIT_TAKE1("PAKEFile", ap_set_file_slot, 
                  (void *)APR_OFFSETOF(auth_tcpcrypt_config_rec, pakefile), OR_AUTHCFG, 
                  "text file containing usernames, pi_0, and L (generated by htpake)"),
    {NULL}
};


#endif // MOD_AUTH_TCPCRYPT_APACHE2_MODULE_INIT_H
