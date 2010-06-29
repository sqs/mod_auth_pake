#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
/* #include <netdb.h> */
/* #include <sys/types.h> */
/* #include <netinet/in.h> */
/* #include <sys/socket.h> */
/* #include <arpa/inet.h> */
#include <curl/curl.h>

#define MAXDATASIZE 100 // max number of bytes we can get at once
#define DEBUG 1

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
			printf("Test FAILED at %s:%d", __FILE__, __LINE__); \
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
};

struct http_response *do_http_request(struct http_request *req) {
    static struct http_response res;
    
    /* reinit */
    res.body.data = NULL;
    res.body.size = 0;
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res.body);
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    res.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res.status);

    if (DEBUG) fprintf(stderr, "GET %s: %ld (%d bytes)\n", req->url, res.status, res.body.size);

    TEST_ASSERT(res.curl_code == 0);

    return &res;
}

void test_authenticates_first_time(void) {
    return;
}

void test_gets_root_unauthenticated(void) {
    struct http_request req;
    req.url = TEST_ROOT_URL;
    struct http_response *res = do_http_request(&req);
    TEST_ASSERT(res->status == 200);
}

static struct test _tests[] = {
    { test_authenicates_first_time, "Authenticates first time"},
    { test_gets_root_unauthenticated, "Gets / without auth"},
};

void run_all_tests(void) {
    for (int i=0; i < ARRAY_SIZE(_tests); ++i) {
        struct test *t = &_tests[i];
        printf("%s\n", t->t_desc);
        t->t_cb();
    }
}

int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    run_all_tests();
    curl_easy_cleanup(curl);
}
