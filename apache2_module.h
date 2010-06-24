#ifndef MOD_AUTH_TCPCRYPT_APACHE2_MODULE_H
#define MOD_AUTH_TCPCRYPT_APACHE2_MODULE_H

#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_time.h"
#include "apr_errno.h"
#include "apr_global_mutex.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

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


/* Disable shmem until pools/init gets sorted out
 * remove following two lines when fixed
 */
#undef APR_HAS_SHARED_MEMORY
#define APR_HAS_SHARED_MEMORY 0



#define DFLT_ALGORITHM  "MD5"

#define DFLT_NONCE_LIFE apr_time_from_sec(300)
#define NEXTNONCE_DELTA apr_time_from_sec(30)


#define NONCE_TIME_LEN  (((sizeof(apr_time_t)+2)/3)*4)
#define NONCE_HASH_LEN  (2*APR_SHA1_DIGESTSIZE)
#define NONCE_LEN       (int )(NONCE_TIME_LEN + NONCE_HASH_LEN)

#define SECRET_LEN      20


/* struct to hold the configuration info */

typedef struct auth_tcpcrypt_config_struct {
    const char  *dir_name;
    authn_provider_list *providers;
    const char  *realm;
    apr_sha1_ctx_t  nonce_ctx;
    apr_time_t    nonce_lifetime;
    const char  *nonce_format;
    const char  *algorithm;
    char        *uri_list;
    const char  *ha1;
} auth_tcpcrypt_config_rec;


/* client list definitions */

typedef struct hash_entry {
    unsigned long      key;                     /* the key for this entry    */
    struct hash_entry *next;                    /* next entry in the bucket  */
    char               ha1[2*APR_MD5_DIGESTSIZE+1];
    char               last_nonce[NONCE_LEN+1]; /* for one-time nonce's      */
} client_entry;


/* struct to hold a parsed Authorization header */

enum hdr_sts { NO_HEADER, NOT_TCPCRYPT_AUTH, INVALID, VALID };

typedef struct auth_tcpcrypt_header_struct {
    const char           *scheme;
    const char           *realm;
    const char           *username;
          char           *nonce;
    const char           *uri;
    const char           *method;
    const char           *digest;
    const char           *algorithm;
    const char           *nonce_count;
    /* the following fields are not (directly) from the header */
    apr_time_t            nonce_time;
    enum hdr_sts          auth_hdr_sts;
    const char           *raw_request_uri;
    apr_uri_t            *psd_request_uri;
    int                   needed_auth;
    client_entry         *client;
} auth_tcpcrypt_header_rec;

#endif // MOD_AUTH_TCPCRYPT_APACHE2_MODULE_H
