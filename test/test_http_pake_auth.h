#ifndef TEST_HTTP_PAKE_AUTH_H
#define TEST_HTTP_PAKE_AUTH_H
#include <curl/curl.h>

#define TEST_HOST "localhost"
#define TEST_PORT "8080"
#define TEST_PROTECTED_PATH "protected/"
#define TEST_PROTECTED_PATH2 "protected/abc.txt"
#define TEST_ROOT_URL "http://" TEST_HOST ":" TEST_PORT "/"
#define TEST_PROTECTED_URL TEST_ROOT_URL TEST_PROTECTED_PATH
#define TEST_PROTECTED_URL2 TEST_ROOT_URL TEST_PROTECTED_PATH2
#define TEST_OPTIONAL_AUTH_URL TEST_ROOT_URL "optional/"
#define TEST_OPTIONAL_AUTH_URL2 TEST_ROOT_URL "optional/xyz.txt"
#define TEST_USER1 "jsmith"
#define TEST_USER2 "alice"
#define TEST_REALM1 "protected area"
#define TEST_OPTIONAL_AUTH_REALM "http://localhost:8080/amcd.json"
#define TEST_PW1 "jsmith"
#define TEST_PW2 "pw"

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

char *header_val(struct http_response *res, char *header_prefix);
void do_http_request(struct http_request *req, struct http_response *res);

#endif // TEST_HTTP_PAKE_AUTH_H
