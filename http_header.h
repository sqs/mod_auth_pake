#ifndef MOD_AUTH_PAKE_TEST_HEADER_H
#define MOD_AUTH_PAKE_TEST_HEADER_H

#include <openssl/ec.h>
#include <openssl/sha.h>
#include "pake.h"

#define MAX_BN_STRING_LENGTH RESP_LENGTH
#define MAX_EC_POINT_STRING_LENGTH (MAX_BN_STRING_LENGTH*2 + 3)

#define PAKE_HTTP_WWW_AUTHENTICATE_STAGE1_LENGTH(hdr) (strlen("Pake realm=\"\"") + strlen((hdr)->realm) + 1)
#define PAKE_HTTP_WWW_AUTHENTICATE_STAGE2_LENGTH(hdr) (strlen("Pake realm=\"\" Y=\"\"") + strlen((hdr)->realm) + MAX_EC_POINT_STRING_LENGTH + 1)
#define PAKE_HTTP_AUTHENTICATION_INFO_LENGTH (strlen("Pake resps=\"\"") + RESP_LENGTH + 1)

enum pake_http_auth_header_type_http {
    HTTP_WWW_AUTHENTICATE,
    HTTP_AUTHORIZATION,
    HTTP_AUTHENTICATION_INFO,
};

enum pake_http_auth_header_type {
    PAKE_HTTP_WWW_AUTHENTICATE_STAGE1,
    PAKE_HTTP_WWW_AUTHENTICATE_STAGE2,
    PAKE_HTTP_AUTHORIZATION_STAGE2,
    PAKE_HTTP_AUTHORIZATION_STAGE1,
    PAKE_HTTP_AUTHENTICATION_INFO
};

struct pake_http_header {
    enum pake_http_auth_header_type type;
    const char *auth_name; /* = Pake */
    const char *username;
    const char *realm;
    char X[MAX_EC_POINT_STRING_LENGTH];
    char Y[MAX_EC_POINT_STRING_LENGTH];
    char respc[RESP_LENGTH];
    char resps[RESP_LENGTH]; 
};

/* Parses header value (only the part after the ":", not the whole line) into
   `header`. */
int pake_http_header_parse(struct pake_http_header *hdr, const char *header_line, enum pake_http_auth_header_type_http type);

/* Write header to string. */
int pake_http_header_stringify(char *header_line, struct pake_http_header *hdr, int value_only);

void pake_http_header_clear(struct pake_http_header *hdr);

/* Print debugging info about header. */
void pake_http_header_inspect(struct pake_http_header *hdr);

#endif // MOD_AUTH_PAKE_TEST_HEADER_H
