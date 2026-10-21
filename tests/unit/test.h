/* Shared harness for the unit suites. Each suite is a void function that
 * records failures through CHECK into one counter; main() runs them all and
 * reports. Add a declaration here when adding a suite file. Printing is the
 * point of a test binary, so tests/ is exempt from the module's no-stdio rule.
 */
#ifndef SSOOSSH_NSS_TEST_H
#define SSOOSSH_NSS_TEST_H

#include <stdio.h>

extern int test_failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL: %s\n", (msg));                                       \
            test_failures++;                                                   \
        }                                                                      \
    } while (0)

void buf_tests(void);
void record_tests(void);
void config_tests(void);
void varlink_tests(void);

#endif /* SSOOSSH_NSS_TEST_H */
