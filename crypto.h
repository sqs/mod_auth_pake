#ifndef MOD_AUTH_TCPCRYPT_CRYPTO_H
#define MOD_AUTH_TCPCRYPT_CRYPTO_H

#include <httpd.h>
#include "apache2_module.h"

const char *get_userpw_hash(const request_rec *r,
                            const auth_tcpcrypt_header_rec *resp,
                            const auth_tcpcrypt_config_rec *conf);

#endif // MOD_AUTH_TCPCRYPT_CRYPTO_H
