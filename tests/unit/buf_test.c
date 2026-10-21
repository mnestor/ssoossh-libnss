/* Unit tests for the NSS result-buffer bump allocator (src/buf.c). Pure and
 * daemon-independent: the buffer protocol is where an off-by-one becomes a
 * heap overwrite inside sshd, so it is tested on its own, boundaries included
 * (exact fit, one byte over, alignment, empty buffer). */
#include "test.h"

#include <stdint.h>
#include <string.h>

#include "buf.h"

/* should copy a string and advance the offset when it fits exactly */
static void test_strdup_exact_fit(void)
{
    char raw[6];
    struct nss_buf b;
    char *p;

    buf_init(&b, raw, sizeof(raw));
    p = buf_strdup(&b, "hello"); /* 5 chars + NUL = 6 */
    CHECK(p == raw, "strdup exact: returns buffer start");
    CHECK(p != NULL && strcmp(p, "hello") == 0, "strdup exact: contents");
    CHECK(b.off == 6, "strdup exact: offset advanced by 6");
}

/* should return NULL when the string is one byte too large */
static void test_strdup_one_over(void)
{
    char raw[5];
    struct nss_buf b;

    buf_init(&b, raw, sizeof(raw));
    CHECK(buf_strdup(&b, "hello") == NULL, "strdup over: returns NULL");
    CHECK(b.off == 0, "strdup over: offset untouched after failure");
}

/* should leave the buffer usable for a smaller request after one overflows */
static void test_failed_alloc_is_recoverable(void)
{
    char raw[4];
    struct nss_buf b;

    buf_init(&b, raw, sizeof(raw));
    CHECK(buf_alloc(&b, 99, 1) == NULL, "recover: large alloc fails");
    CHECK(buf_strdup(&b, "ab") != NULL, "recover: small alloc then succeeds");
}

/* should align a reservation to the requested power of two */
static void test_alignment(void)
{
    char raw[64];
    struct nss_buf b;
    void *p;

    buf_init(&b, raw, sizeof(raw));
    CHECK(buf_alloc(&b, 1, 1) != NULL, "align: one unaligned byte");
    p = buf_alloc(&b, sizeof(long), sizeof(long));
    CHECK(p != NULL, "align: aligned reservation fits");
    CHECK(p != NULL && ((uintptr_t)p % sizeof(long)) == 0,
          "align: pointer is aligned");
}

/* should report NULL for any request against a zero-length buffer */
static void test_empty_buffer(void)
{
    struct nss_buf b;

    buf_init(&b, NULL, 0);
    CHECK(buf_alloc(&b, 1, 1) == NULL, "empty: one byte fails");
    CHECK(buf_strdup(&b, "") == NULL, "empty: even the NUL fails");
}

void buf_tests(void)
{
    test_strdup_exact_fit();
    test_strdup_one_over();
    test_failed_alloc_is_recoverable();
    test_alignment();
    test_empty_buffer();
}
