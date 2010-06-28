#include <stdio.h>
#include <stdlib.h>


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

static struct test _tests[] = {
    { test_authenicates_first_time, "Authenticates first time"},
};

void run_all_tests(void) {
    for (int i=0; i < ARRAY_SIZE(_tests); ++i) {
        struct test *t = &_tests[i];
        printf("%s\n", t->t_desc);
    }
}

int main(int argc, char **argv) {
    run_all_tests();
}
