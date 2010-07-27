#ifndef MOD_AUTH_PAKE_APACHE2_MODULE_H
#define MOD_AUTH_PAKE_APACHE2_MODULE_H

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

#include "http_header.h"
#include "pake.h"


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




/* client list definitions */

typedef struct hash_entry {
    unsigned long      key;                     /* the key for this entry    */
    struct hash_entry *next;                    /* next entry in the bucket  */
} client_entry;


/* struct to hold a parsed Authorization header */

enum hdr_sts { NO_HEADER, NOT_PAKE_AUTH, INVALID, VALID_STAGE1, VALID_STAGE2 };

typedef struct auth_pake_header_struct {
    struct pake_http_header hdr;
    enum hdr_sts          auth_hdr_sts;
    const char           *method;
    const char           *uri;
    const char           *raw_request_uri;
    apr_uri_t            *psd_request_uri;
    int                   needed_auth;
    int                   auth_ok;
    client_entry         *client;
} auth_pake_header_rec;

#endif // MOD_AUTH_PAKE_APACHE2_MODULE_H
