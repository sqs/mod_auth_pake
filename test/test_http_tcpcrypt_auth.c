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

struct http_response *do_http_request(struct http_request *req) {
    static struct http_response res;
    
    /* reinit */
    if (res.body.data) free(res.body.data);
    res.body.data = NULL;
    res.body.size = 0;
    res.headers = NULL;
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res.body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&res);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    res.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res.status);

    if (detailed) fprintf(stderr, "GET %s: %ld (%d bytes)\n", req->url, res.status, res.body.size);
    if (detailed) headers_inspect(&res);
    /* if (detailed) printf("%s", res.body.data); */

    if (res.curl_code != 0) {
        fprintf(stderr, "expected curl_code=0, got %d\n", res.curl_code);
        TEST_ASSERT(res.curl_code == 0);
    }

    return &res;
}

void test_auth_challenge(void) {
    struct http_request req;
    req.url = TEST_PROTECTED_URL;
    struct http_response *res = do_http_request(&req);
    TEST_ASSERT(res->status == 401);

    char *www_auth = header_val(res, "WWW-Authenticate");
    if (detailed) fprintf(stderr, "WWW-Authenticate: %s\n", www_auth);
    TEST_ASSERT(www_auth != NULL);
    TEST_ASSERT(strstr(www_auth, " Tcpcrypt ") == www_auth);

    struct http_tcpcrypt_auth_chal chal;
    memset(&chal, 0, sizeof(struct http_tcpcrypt_auth_chal));
    parse_auth_chal(&chal, www_auth);
    if (detailed) inspect_auth_chal(&chal);
    TEST_ASSERT(chal.auth_name && strcmp(chal.auth_name, "Tcpcrypt") == 0);
    TEST_ASSERT(chal.realm && strcmp(chal.realm, "protected area") == 0);
    TEST_ASSERT(chal.domain && strcmp(chal.domain, "/protected/ http://localhost:8080/protected/") == 0);
    TEST_ASSERT(chal.nonce && strlen(chal.nonce) == 52);
}

void test_authenticates_first_time(void) {
    struct http_request req;
    req.url = TEST_PROTECTED_URL;
    struct http_response *res = do_http_request(&req);
    TEST_ASSERT(res->status == 401);

    char *www_auth = header_val(res, "WWW-Authenticate");
    struct http_tcpcrypt_auth_chal chal;
    memset(&chal, 0, sizeof(struct http_tcpcrypt_auth_chal));
    parse_auth_chal(&chal, www_auth);
    
    if (detailed) inspect_auth_chal(&chal);

    
}

void test_gets_root_unauthenticated(void) {
    struct http_request req;
    req.url = TEST_ROOT_URL;
    struct http_response *res = do_http_request(&req);
    TEST_ASSERT(res->status == 200);
}

void test_make_ha1(void) {
    char ha1[33];
    make_ha1(ha1, "jsmith", "protected area", "jsmith");
    ha1[32] = '\0';
    char exp_ha1[] = "a6ee4e8e8b478bbf7b7a98317597e070";
    TEST_ASSERT(strncmp(exp_ha1, ha1, strlen(exp_ha1)) == 0);
}

static struct test _tests[] = {
    { test_authenticates_first_time, "authsingle"},
    { test_gets_root_unauthenticated, "noauth"},
    { test_auth_challenge, "chal"},
    { test_make_ha1, "make_ha1"},
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
