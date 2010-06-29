#ifndef MOD_AUTH_TCPCRYPT_TEST_PARSER_H
#define MOD_AUTH_TCPCRYPT_TEST_PARSER_H

struct http_tcpcrypt_auth_chal {
    char *auth_name;
    char *realm;
    char *nonce;
    char *domain;
};

void parse_auth_chal(struct http_tcpcrypt_auth_chal *chal, const char *header);

void inspect_auth_chal(struct http_tcpcrypt_auth_chal *chal);


#endif // MOD_AUTH_TCPCRYPT_TEST_PARSER_H
