#ifndef TEST_HTTP_TCPCRYPT_AUTH_H
#define TEST_HTTP_TCPCRYPT_AUTH_H
#include <curl/curl.h>

struct http_request {
    char *url;
    char *user;
    char *pw;
    char *realm;
};

struct chunk {
  char *data;
  size_t size;
};

struct http_response {
    CURLcode curl_code;
    long int status;
    struct chunk body;
    struct curl_slist *headers;
};

#endif // TEST_HTTP_TCPCRYPT_AUTH_H
