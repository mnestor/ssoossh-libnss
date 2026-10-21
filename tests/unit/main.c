#include "test.h"

/* The one definition of the shared failure counter. */
int test_failures = 0;

int main(void)
{
    buf_tests();
    record_tests();
    config_tests();
    varlink_tests();

    if (test_failures != 0) {
        printf("unit: %d failure(s)\n", test_failures);
        return 1;
    }
    printf("unit: ok\n");
    return 0;
}
