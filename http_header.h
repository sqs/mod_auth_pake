#ifndef MOD_AUTH_TCPCRYPT_TEST_HEADER_H
#define MOD_AUTH_TCPCRYPT_TEST_HEADER_H

struct tcpcrypt_http_header {
    enum { HTTP_WWW_AUTHENTICATE, 
           HTTP_AUTHORIZATION,
           HTTP_AUTHENTICATION_INFO
    } type;
    char *auth_name; /* = Tcpcrypt */
    char *username;
    char *realm;
    char *X;
    char *Y;
    char *respc;
    char *resps;
};

/* Parses header value (only the part after the ":", not the whole line) into
   `header`. */
int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *info, const char *header_line);

/* Write header to string. */
int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *info);

/* Print debugging info about header. */
void tcpcrypt_http_header_inspect(struct tcpcrypt_http_header *info);


#endif // MOD_AUTH_TCPCRYPT_TEST_HEADER_H
