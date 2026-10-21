/* Unit tests for the initgroups gid-array growth (src/gidlist.c). Starts from
 * a NULL array, as glibc may, and checks append, growth, dedup and the limit.
 */
#include "test.h"

#include <stdlib.h>

#include "gidlist.h"

/* should append into a fresh (NULL) array, allocating it */
static void test_append_from_empty(void)
{
    gid_t *g = NULL;
    long start = 0, size = 0;

    CHECK(gidlist_add(&g, &start, &size, 0, 5) == 0, "empty: append ok");
    CHECK(start == 1, "empty: start advanced");
    CHECK(g != NULL && g[0] == 5, "empty: value stored");
    free(g);
}

/* should skip a gid already present */
static void test_dedup(void)
{
    gid_t *g = NULL;
    long start = 0, size = 0;

    gidlist_add(&g, &start, &size, 0, 5);
    CHECK(gidlist_add(&g, &start, &size, 0, 5) == 1, "dedup: returns skipped");
    CHECK(start == 1, "dedup: start unchanged");
    free(g);
}

/* should grow past the initial capacity preserving earlier values */
static void test_growth(void)
{
    gid_t *g = NULL;
    long start = 0, size = 0;
    int i, ok = 1;

    for (i = 0; i < 100; i++) {
        if (gidlist_add(&g, &start, &size, 0, (gid_t)(1000 + i)) != 0) {
            ok = 0;
        }
    }
    CHECK(ok == 1, "growth: all appended");
    CHECK(start == 100, "growth: count is 100");
    CHECK(g != NULL && g[0] == 1000 && g[99] == 1099, "growth: ends intact");
    free(g);
}

/* should stop appending once a positive limit is reached */
static void test_limit(void)
{
    gid_t *g = NULL;
    long start = 0, size = 0;

    CHECK(gidlist_add(&g, &start, &size, 2, 10) == 0, "limit: first ok");
    CHECK(gidlist_add(&g, &start, &size, 2, 11) == 0, "limit: second ok");
    CHECK(gidlist_add(&g, &start, &size, 2, 12) == 1, "limit: third skipped");
    CHECK(start == 2, "limit: capped at 2");
    free(g);
}

void gidlist_tests(void)
{
    test_append_from_empty();
    test_dedup();
    test_growth();
    test_limit();
}
