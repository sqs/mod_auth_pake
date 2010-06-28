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

#define TEST_HOST "localhost"
#define TEST_PORT "8080"
#define TEST_PATH "/protected/"
#define TEST_USER1 "jsmith"
#define TEST_PW1 "jsmith"

static CURL *curl;

#define TEST_ASSERT(n)					                     \
	do {								     \
		if (!(n)) 						     \
			errx(1, "Test FAILED at %s:%d", __FILE__, __LINE__); \
	} while (0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))


struct test {
	void	(*t_cb)(void);
	char	*t_desc;
};



void test_authenicates_first_time(void) {
    return;
}

void test_gets_root_unauthenticated(void) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/");
    CURLcode success = curl_easy_perform(curl);
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
    run_all_tests();
    curl_easy_cleanup(curl);
}
