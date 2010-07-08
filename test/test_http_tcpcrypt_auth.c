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
#include <openssl/sha.h>
#include <assert.h>
#include "tcpcrypt_session.h"
#include "http_header.h"
#include "http_tcpcrypt_auth.h"
#include "test_pake.h"
#include "pake.h"

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

#define CLEAR_HEADER(hdr) memset((void *)&hdr, 0, sizeof(hdr))

static CURL *curl;

#define TEST_ASSERT(n)					                     \
	do {								     \
		if (!(n)) 						     \
			printf("Test FAILED at %s:%d\n", __FILE__, __LINE__); \
	} while (0)

void TEST_ASSERT_STREQ(const char *s1, const char *s2) {
    if (strcmp(s1, s2)) {
        fprintf(stderr, "TEST_ASSERT_STREQ: expected %s, got %s\n", s1, s2);
        assert(strcmp(s1, s2) == 0);
    }
}

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
char *header_val(struct http_response *res, char *header_prefix) {
    struct curl_slist *e;
    
    char *header_line = NULL;
    for (e = res->headers; e != NULL; e = e->next) {
       header_line = e->data;
        if (strncmp(header_prefix, header_line, strlen(header_prefix)) == 0) {
            return header_line + strlen(header_prefix); /* begin after ":" */
        }
    }
    return NULL;
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

void get_hdr(char *k, enum tcpcrypt_http_auth_header_type type, struct http_request *req, struct http_response *res, struct tcpcrypt_http_header *hdr) {
    char *header_line = header_val(res, k);

    if (!header_line) {
        fprintf(stderr, "get_hdr: couldn't get header '%s'\n", k);
        return;
    }

    memset(hdr, 0, sizeof(struct tcpcrypt_http_header));
    tcpcrypt_http_header_parse(hdr, header_line, type);
}

void test_apache_www_authenticate_hdr(void) {
    struct http_request req;
    struct http_response res;
    struct tcpcrypt_http_header hdr;
    CLEAR_HEADER(hdr);
    
    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    get_hdr("WWW-Authenticate:", HTTP_WWW_AUTHENTICATE, &req, &res, &hdr);
    TEST_ASSERT(res.status == 401);

    char *www_auth = header_val(&res, "WWW-Authenticate:");
    if (detailed) fprintf(stderr, "%s\n", www_auth);
    TEST_ASSERT(www_auth != NULL);

    if (detailed) tcpcrypt_http_header_inspect(&hdr);
    TEST_ASSERT(hdr.type == HTTP_WWW_AUTHENTICATE);
    TEST_ASSERT_STREQ("Tcpcrypt", hdr.auth_name);
    TEST_ASSERT_STREQ("protected area", hdr.realm);
    TEST_ASSERT(hdr.Y != NULL);
    printf("--- '%s'\n", hdr.Y);
    TEST_ASSERT(strlen(hdr.Y) > 30);
    TEST_ASSERT_STREQ("", hdr.X);
    TEST_ASSERT(hdr.username == NULL);
    TEST_ASSERT(hdr.resps[0] == '\0');
    TEST_ASSERT(hdr.respc[0] == '\0');
}

void make_auth_hdr(char *header_line, struct tcpcrypt_http_header *res_hdr, char *exp_resps, char *username, char *realm, char *password) {
    struct tcpcrypt_http_header req_hdr;
    CLEAR_HEADER(req_hdr);

    req_hdr.type = HTTP_AUTHORIZATION;
    req_hdr.username = username;
    req_hdr.realm = realm;

    struct pake_info pc;
    BN_CTX *ctx = NULL;
    memset(&pc, 0, sizeof(pc));
    assert(ctx = BN_CTX_new());
    BN_CTX_start(ctx);
    assert(pake_client_init(&pc, ctx));
    assert(pake_client_set_credentials(&pc, username, realm, password, ctx));

    EC_POINT *Y = EC_POINT_new(pc.public.G);
    EC_POINT_hex2point(pc.public.G, res_hdr->Y, Y, ctx);
    pake_client_recv_Y(&pc, Y);
    assert(pc.client_state.X);
    assert(pc.client_state.server_Y);
    
    char *s;
    s = EC_POINT_point2hex(pc.public.G, pc.client_state.X, POINT_CONVERSION_UNCOMPRESSED, ctx);
    strcpy(req_hdr.X, s);
    OPENSSL_free(s);
    
    tcpcrypt_pake_compute_respc(&pc, tcpcrypt_get_sid(), ctx);
    strcpy(req_hdr.respc, (char *)pc.shared.respc);

    assert(tcpcrypt_http_header_stringify(header_line, &req_hdr, 0)); 
    if (detailed) printf("make auth hdr: '%s'\n", header_line);

    /* save expected resps to exp_resps */
    tcpcrypt_pake_compute_resps(&pc, tcpcrypt_get_sid(), ctx);
    strcpy(exp_resps, (char *)pc.shared.resps);
}

void set_auth_hdr(CURL *curl_, char *auth_hdr) {
    /* set header */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
}

void test_apache_authorizes(void) {
    struct http_request req;
    struct http_response res;
    struct tcpcrypt_http_header hdr;
    CLEAR_HEADER(hdr);
    
    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    get_hdr("WWW-Authenticate:", HTTP_WWW_AUTHENTICATE, &req, &res, &hdr);
    TEST_ASSERT(res.status == 401);
    if (res.status != 401) return;
    
    if (detailed) tcpcrypt_http_header_inspect(&hdr);

    char auth_hdr[1000], exp_resps[RESP_LENGTH];
    make_auth_hdr(auth_hdr, &hdr, exp_resps, TEST_USER1, TEST_REALM1, TEST_PW1);
    set_auth_hdr(curl, auth_hdr);

    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 200);
    
    /* check resps */
    CLEAR_HEADER(hdr);
    get_hdr("Authentication-Info:", HTTP_AUTHENTICATION_INFO, &req, &res, &hdr);
    TEST_ASSERT_STREQ(exp_resps, hdr.resps);
}

void test_apache_rejects_bad_username(void) {
    struct http_request req;
    struct http_response res;
    struct tcpcrypt_http_header hdr;
    CLEAR_HEADER(hdr);
    
    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    get_hdr("WWW-Authenticate:", HTTP_WWW_AUTHENTICATE, &req, &res, &hdr);
    TEST_ASSERT(res.status == 401);

    char auth_hdr[1000], exp_resps[RESP_LENGTH];
    make_auth_hdr(auth_hdr, &hdr, exp_resps, "baduser", TEST_REALM1, TEST_PW1);
    set_auth_hdr(curl, auth_hdr);

    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 401);
    
    /* check resps */
    CLEAR_HEADER(hdr);
    assert(!header_val(&res, "Authentication-Info:"));
}


void test_apache_rejects_bad_realm(void) {
    struct http_request req;
    struct http_response res;
    struct tcpcrypt_http_header hdr;
    CLEAR_HEADER(hdr);
    
    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    get_hdr("WWW-Authenticate:", HTTP_WWW_AUTHENTICATE, &req, &res, &hdr);
    TEST_ASSERT(res.status == 401);

    char auth_hdr[1000], exp_resps[RESP_LENGTH];
    make_auth_hdr(auth_hdr, &hdr, exp_resps, TEST_USER1, "badrealm", TEST_PW1);
    set_auth_hdr(curl, auth_hdr);

    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 401);
    
    /* check resps */
    CLEAR_HEADER(hdr);
    assert(!header_val(&res, "Authentication-Info:"));
}

void test_gets_root_unauthenticated(void) {
    struct http_request req;
    struct http_response res;
    req.url = TEST_ROOT_URL;
    do_http_request(&req, &res);
    TEST_ASSERT(res.status == 200);
}

void test_www_authenticate_hdr(void) {
    struct tcpcrypt_http_header hdr;
    
    /* parse test */
    CLEAR_HEADER(hdr);
    TEST_ASSERT(tcpcrypt_http_header_parse(&hdr, " Tcpcrypt realm=\"protected area\" Y=\"0123456789abcdef\"", HTTP_WWW_AUTHENTICATE));
    TEST_ASSERT(hdr.type == HTTP_WWW_AUTHENTICATE);
    TEST_ASSERT_STREQ(hdr.auth_name, "Tcpcrypt");
    TEST_ASSERT(hdr.username == NULL);
    TEST_ASSERT_STREQ(hdr.realm, "protected area");
    TEST_ASSERT(strlen(hdr.X) == 0);
    TEST_ASSERT_STREQ(hdr.Y, "0123456789abcdef");
    TEST_ASSERT(strlen(hdr.respc) == 0);
    TEST_ASSERT(strlen(hdr.resps) == 0);

    /* stringify test */
    CLEAR_HEADER(hdr);
    hdr.type = HTTP_WWW_AUTHENTICATE;
    hdr.realm = "protected area";
    strcpy(hdr.Y, "0123456789abcdef");
    char header_line[1000];
    memset((void *)&header_line, 0, sizeof(header_line));
    TEST_ASSERT(tcpcrypt_http_header_stringify(header_line, &hdr, 0));
    char *exp_header_line = "WWW-Authenticate: Tcpcrypt realm=\"protected area\" Y=\"0123456789abcdef\"";
    TEST_ASSERT_STREQ(exp_header_line, header_line);
}

static struct test _tests[] = {
    { test_pake, "test_pake" },
    { test_apache_authorizes, "test_apache_authorizes"},
    { test_gets_root_unauthenticated, "test_gets_root_unauthenticated"},
    { test_apache_www_authenticate_hdr, "test_apache_www_authenticate_hdr"},
    { test_www_authenticate_hdr, "test_www_authenticate_hdr" },
    { test_apache_rejects_bad_username, "test_apache_rejects_bad_username" },
    { test_apache_rejects_bad_realm, "test_apache_rejects_bad_realm" },
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
