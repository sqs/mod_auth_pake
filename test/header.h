#ifndef MOD_AUTH_TCPCRYPT_TEST_HEADER_H
#define MOD_AUTH_TCPCRYPT_TEST_HEADER_H

struct tcpcrypt_http_header {
    char *auth_name;
    char *realm;
    char *gBVpi0;
    char *gaUpi0;
    char *rc;
    char *rs;
};

/* Parses header value (only the part after the ":", not the whole line) into
   `header`. */
void parse_header(struct tcpcrypt_http_header *info, const char *header_val);

void inspect_header(struct tcpcrypt_http_header *info);


#endif // MOD_AUTH_TCPCRYPT_TEST_HEADER_H
