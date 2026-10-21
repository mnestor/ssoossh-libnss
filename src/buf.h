#ifndef SSOOSSH_NSS_BUF_H
#define SSOOSSH_NSS_BUF_H

#include <stddef.h>

/* A bump allocator over the fixed result buffer every NSS _r entry point is
 * handed. NSS forbids heap allocation for returned strings and arrays: they
 * must live in the caller's buffer, and when they do not fit the entry point
 * returns NSS_STATUS_TRYAGAIN with errno ERANGE so the caller retries with a
 * larger one. Every reservation here returns NULL on overflow, which the
 * entry points translate into exactly that. */
struct nss_buf {
    char *base; /* start of the caller's buffer */
    size_t len; /* its size in bytes */
    size_t off; /* bytes handed out so far (0 <= off <= len) */
};

/* Initialise over a caller-provided buffer. */
void buf_init(struct nss_buf *b, char *base, size_t len);

/* Reserve n bytes aligned to `align`, which must be a power of two. Returns a
 * pointer into the buffer, or NULL if the aligned reservation does not fit. A
 * failed call does not advance the offset, so a smaller one can still
 * succeed. */
void *buf_alloc(struct nss_buf *b, size_t n, size_t align);

/* Copy a NUL-terminated string into the buffer and return the copy, or NULL
 * if it does not fit. */
char *buf_strdup(struct nss_buf *b, const char *s);

#endif /* SSOOSSH_NSS_BUF_H */
