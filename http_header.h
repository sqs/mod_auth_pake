#ifndef MOD_AUTH_TCPCRYPT_TEST_HEADER_H
#define MOD_AUTH_TCPCRYPT_TEST_HEADER_H

#include <openssl/ec.h>

#define MAX_BN_STRING_LENGTH 100
#define MAX_EC_POINT_STRING_LENGTH (MAX_BN_STRING_LENGTH*2 + 3)

enum tcpcrypt_http_auth_header_type {
    HTTP_WWW_AUTHENTICATE, 
    HTTP_AUTHORIZATION,
    HTTP_AUTHENTICATION_INFO
};

struct tcpcrypt_http_header {
    enum tcpcrypt_http_auth_header_type type;
    char *auth_name; /* = Tcpcrypt */
    char *username;
    char *realm;
    char X[MAX_EC_POINT_STRING_LENGTH];
    char Y[MAX_EC_POINT_STRING_LENGTH];
    char *respc;
    char *resps;
};

/* Parses header value (only the part after the ":", not the whole line) into
   `header`. */
int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *info, const char *header_line, enum tcpcrypt_http_auth_header_type type);

/* Write header to string. */
int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *info, int value_only);

/* Print debugging info about header. */
void tcpcrypt_http_header_inspect(struct tcpcrypt_http_header *info);

#endif // MOD_AUTH_TCPCRYPT_TEST_HEADER_H
