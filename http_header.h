#ifndef MOD_AUTH_TCPCRYPT_TEST_HEADER_H
#define MOD_AUTH_TCPCRYPT_TEST_HEADER_H

#include <openssl/ec.h>
#include <openssl/sha.h>
#include "pake.h"

#define MAX_BN_STRING_LENGTH RESP_LENGTH
#define MAX_EC_POINT_STRING_LENGTH (MAX_BN_STRING_LENGTH*2 + 3)

#define TCPCRYPT_HTTP_WWW_AUTHENTICATE_STAGE1_LENGTH(hdr) (strlen("Tcpcrypt realm=\"\"") + strlen((hdr)->realm) + 1)
#define TCPCRYPT_HTTP_WWW_AUTHENTICATE_STAGE2_LENGTH(hdr) (strlen("Tcpcrypt realm=\"\" Y=\"\"") + strlen((hdr)->realm) + MAX_EC_POINT_STRING_LENGTH + 1)
#define TCPCRYPT_HTTP_AUTHENTICATION_INFO_LENGTH (strlen("Tcpcrypt resps=\"\"") + RESP_LENGTH + 1)

enum tcpcrypt_http_auth_header_type_http {
    HTTP_WWW_AUTHENTICATE,
    HTTP_AUTHORIZATION,
    HTTP_AUTHENTICATION_INFO,
};

enum tcpcrypt_http_auth_header_type {
    TCPCRYPT_HTTP_WWW_AUTHENTICATE_STAGE1,
    TCPCRYPT_HTTP_WWW_AUTHENTICATE_STAGE2,
    TCPCRYPT_HTTP_AUTHORIZATION_STAGE2,
    TCPCRYPT_HTTP_AUTHORIZATION_STAGE1,
    TCPCRYPT_HTTP_AUTHENTICATION_INFO
};

struct tcpcrypt_http_header {
    enum tcpcrypt_http_auth_header_type type;
    const char *auth_name; /* = Tcpcrypt */
    const char *username;
    const char *realm;
    char X[MAX_EC_POINT_STRING_LENGTH];
    char Y[MAX_EC_POINT_STRING_LENGTH];
    char respc[RESP_LENGTH];
    char resps[RESP_LENGTH]; 
};

/* Parses header value (only the part after the ":", not the whole line) into
   `header`. */
int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *hdr, const char *header_line, enum tcpcrypt_http_auth_header_type_http type);

/* Write header to string. */
int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *hdr, int value_only);

void tcpcrypt_http_header_clear(struct tcpcrypt_http_header *hdr);

/* Print debugging info about header. */
void tcpcrypt_http_header_inspect(struct tcpcrypt_http_header *hdr);

#endif // MOD_AUTH_TCPCRYPT_TEST_HEADER_H
