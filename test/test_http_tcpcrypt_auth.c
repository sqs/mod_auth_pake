#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
/* #include <netdb.h> */
/* #include <sys/types.h> */
/* #include <netinet/in.h> */
/* #include <sys/socket.h> */
/* #include <arpa/inet.h> */
#include <curl/curl.h>
#include "tcpcrypt_session.h"
#include "parser.h"
#include "http_tcpcrypt_auth.h"

#define MAXDATASIZE 100 // max number of bytes we can get at once
static int detailed = 0; // level of detail for tests

#define TEST_HOST "localhost"
#define TEST_PORT "8080"
#define TEST_PROTECTED_PATH "protected/"
#define TEST_ROOT_URL "http://" TEST_HOST ":" TEST_PORT "/"
#define TEST_PROTECTED_URL TEST_ROOT_URL TEST_PROTECTED_PATH
#define TEST_USER1 "jsmith"
#define TEST_REALM1 "protected area"
#define TEST_PW1 "jsmith"

static CURL *curl;

#define TEST_ASSERT(n)					                     \
	do {								     \
		if (!(n)) 						     \
			printf("Test FAILED at %s:%d\n", __FILE__, __LINE__); \
	} while (0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct test {
    void	(*t_cb)(void);
    char	*t_desc;
};


/*************************************************
 * HTTP stuff
 */

struct chunk {
  char *data;
  size_t size;
};

static size_t
WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct chunk *mem = (struct chunk *)data;
 
  mem->data = realloc(mem->data, mem->size + realsize + 1);
  if (mem->data) {
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
  }
  return realsize;
}


struct http_request {
    char *url;
    char *user;
    char *pw;
    char *realm;
};

struct http_response {
    CURLcode curl_code;
    long int status;
    struct chunk body;
    struct curl_slist *headers;
};

static size_t
header_callback(void *ptr, size_t size, size_t nmemb, void *res_) {
    size_t realsize = size*nmemb;
    struct http_response *res = res_;
    char *header_line = malloc(realsize+1);
    memcpy(header_line, ptr, realsize);
    header_line[realsize] = '\0';
    res->headers = curl_slist_append(res->headers, header_line);

    return realsize;
}

void headers_inspect(struct http_response *res) {
    struct curl_slist *e;
    for (e = res->headers; e != NULL; e = e->next) {
        char *header_line = e->data;
        printf("%s", header_line);
    }
}

/* Returns the NULL-terminated value of the HTTP header with name `k`,
   or NULL if it's not found. */
char *header_val(struct http_response *res, char *k) {
    char *val = NULL;
    char *header_prefix;
    struct curl_slist *e;
    
    header_prefix = malloc(strlen(k) + 2); // len + ':' + '\0'
    strcpy(header_prefix, k);
    strcat(header_prefix, ":");

    for (e = res->headers; e != NULL; e = e->next) {
        char *header_line = e->data;
        char *m = strstr(header_line, header_prefix);
        if (m == header_line) {
            val = &header_line[strlen(header_prefix)];
            break;
        }
    }

    free(header_prefix);
    return val;
}

void do_http_request(struct http_request *req, struct http_response *res) {
    /* reinit */
    memset(res, '\0', sizeof(struct http_response));
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res->body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)res);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    res->curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res->status);

    if (detailed) fprintf(stderr, "GET %s: %ld (%d bytes)\n", req->url, res->status, res->body.size);
    if (detailed) headers_inspect(res);
    /* if (detailed) printf("%s", res->body.data); */

    if (res->curl_code != 0) {
        fprintf(stderr, "expected curl_code=0, got %d\n", res->curl_code);
        TEST_ASSERT(res->curl_code == 0);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
}

void get_auth_challenge(struct http_request *req, struct http_response *res, struct http_tcpcrypt_auth_chal *chal) {
    do_http_request(req, res);
    char *www_auth = header_val(res, "WWW-Authenticate");

    memset(chal, 0, sizeof(struct http_tcpcrypt_auth_chal));
    parse_auth_chal(chal, www_auth);
}

void test_auth_challenge(void) {
    struct http_request req;
    struct http_response res;
    struct http_tcpcrypt_auth_chal chal;
    
    req.url = TEST_PROTECTED_URL;
    get_auth_challenge(&req, &res, &chal);
    TEST_ASSERT(res.status == 401);

    char *www_auth = header_val(&res, "WWW-Authenticate");
    if (detailed) fprintf(stderr, "WWW-Authenticate: %s\n", www_auth);
    TEST_ASSERT(www_auth != NULL);
    TEST_ASSERT(strstr(www_auth, " Tcpcrypt ") == www_auth);

    if (detailed) inspect_auth_chal(&chal);
    TEST_ASSERT(chal.auth_name && strcmp(chal.auth_name, "Tcpcrypt") == 0);
    TEST_ASSERT(chal.realm && strcmp(chal.realm, "protected area") == 0);
    TEST_ASSERT(chal.domain && strcmp(chal.domain, "/protected/ http://localhost:8080/protected/") == 0);
    TEST_ASSERT(chal.nonce && strlen(chal.nonce) == 52);
}

void make_auth_hdr(char *hdr, struct http_tcpcrypt_auth_chal *chal) {
    char ha1[33];
    make_ha1(ha1, TEST_USER1, TEST_REALM1, TEST_PW1);
    ha1[32] = '\0';
    char resp[33];
    make_response(resp, ha1, chal->nonce, tcpcrypt_get_sid());
    resp[32] = '\0';

    /* construct Authorization header */
    sprintf(hdr,
            "Authorization: Tcpcrypt username=\"%s\", " \
            "realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
            TEST_USER1, TEST_REALM1, chal->nonce, TEST_PROTECTED_URL, resp);
 
}

void set_auth_hdr(CURL *curl_, char *auth_hdr) {
    /* set header */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
}

void parse_auth_info_rspauth(char *rspauth, char *auth_info) {
    /* since rspauth is the only thing contained in the
       Authentication-Info header, just use substrings
       instead of an actual tokenizer
    */
    const size_t rspauth_digest_len = 32;
    if (auth_info[0] == ' ') auth_info++;
    auth_info += strlen("rspauth=\"");
    memcpy(rspauth, auth_info, rspauth_digest_len);
    rspauth[rspauth_digest_len] = '\0';
}

void test_auth_info(void) {
    struct http_request req;
    struct http_response res;
    struct http_tcpcrypt_auth_chal chal;
    
    req.url = TEST_PROTECTED_URL;
    get_auth_challenge(&req, &res, &chal);
    TEST_ASSERT(res.status == 401);
    
    char auth_hdr[1000];
    make_auth_hdr(auth_hdr, &chal);
    set_auth_hdr(curl, auth_hdr);

    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 200);

    /* check auth-info */
    char *auth_info = header_val(&res, "Authentication-Info");
    char rspauth[33];
    parse_auth_info_rspauth(rspauth, auth_info);

    /* make expected rspauth: MD5(HA1, sid) */
    char exp_rspauth[33];
    char ha1[33];
    make_ha1(ha1, "jsmith", "protected area", "jsmith");
    ha1[32] = '\0';
    make_response(exp_rspauth, ha1, chal.nonce, tcpcrypt_get_sid());

    TEST_ASSERT(strcmp(exp_rspauth, rspauth) == 0);
}

void test_authenticates_first_time(void) {
    struct http_request req;
    struct http_response res;
    struct http_tcpcrypt_auth_chal chal;
    
    req.url = TEST_PROTECTED_URL;
    get_auth_challenge(&req, &res, &chal);
    TEST_ASSERT(res.status == 401);
    
    if (detailed) inspect_auth_chal(&chal);

    char auth_hdr[1000];
    make_auth_hdr(auth_hdr, &chal);
    set_auth_hdr(curl, auth_hdr);

    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 200);
}

void test_gets_root_unauthenticated(void) {
    struct http_request req;
    struct http_response res;
    req.url = TEST_ROOT_URL;
    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 200);
}

void test_make_ha1(void) {
    char ha1[33];
    make_ha1(ha1, "jsmith", "protected area", "jsmith");
    ha1[32] = '\0';
    char exp_ha1[] = "a6ee4e8e8b478bbf7b7a98317597e070";
    TEST_ASSERT(strncmp(exp_ha1, ha1, strlen(exp_ha1)) == 0);
}

void test_make_response(void) {
    char resp[33];
    make_response(resp, "aaaabbbbccccddddeeeeffff00001111", 
                  "1111222233334444555566667777888899990000aa",
                  1122334455);
    char exp_resp[] = "66130504aac9beb441806ad9c1c8f245";
    TEST_ASSERT(strncmp(exp_resp, resp, strlen(exp_resp)) == 0);
}

static struct test _tests[] = {
    { test_authenticates_first_time, "authsingle"},
    { test_gets_root_unauthenticated, "noauth"},
    { test_auth_challenge, "chal"},
    { test_auth_info, "auth_info" },
    { test_make_ha1, "make_ha1"},
    { test_make_response, "make_response" },
};

/* Run tests matching spec, or all tests if spec is NULL. */
void run_tests(char *spec) {
    detailed = 1;
    if (spec == NULL) {
        spec = "";
        detailed = 0;
    }
    for (int i=0; i < ARRAY_SIZE(_tests); ++i) {
        struct test *t = &_tests[i];
        if (strstr(t->t_desc, spec)) {
            fprintf(stderr, "*** %s\n", t->t_desc);
            t->t_cb();
        }
    }
}

int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    run_tests(argc == 1 ? NULL : argv[1]);
    curl_easy_cleanup(curl);
}
