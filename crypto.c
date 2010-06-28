#include "crypto.h"
#include "apache2_module.h"


static const char *ltox(apr_pool_t *p, unsigned long num)
{
    if (num != 0) { /* XXX should output "0" for 0? */
        return apr_psprintf(p, "%lx", num);
    }
    else {
        return "";
    }
}

/*
 * get_userpw_hash() will be called each time a new session needs to be
 * generated and returns
 *
 *   MD5(nonce ":" realm ":" password ":" tcpcrypt_sid)
 *
 */

const char *get_userpw_hash(const request_rec *r,
                            const auth_tcpcrypt_header_rec *resp,
                            const auth_tcpcrypt_config_rec *conf)
{
    unsigned char *resp_plain = apr_pstrcat(r->pool,
                                            conf->ha1, ":",
                                            resp->nonce, ":",
                                            ltox(r->pool, tcpcrypt_get_sid()),
                                            NULL);
    return ap_md5(r->pool, resp_plain);
}
