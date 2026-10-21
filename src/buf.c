#include "buf.h"

#include <stdint.h>
#include <string.h>

/* Initialise over a caller-provided buffer. */
void buf_init(struct nss_buf *b, char *base, size_t len)
{
    b->base = base;
    b->len = len;
    b->off = 0;
}

/* Reserve n bytes aligned to `align`. The padding is computed on the real
 * address, not merely the offset, so the returned pointer is aligned for the
 * caller's struct even when the buffer glibc handed us is not itself aligned.
 * Each bound is checked against the remaining space before the offset is
 * advanced, so overflow returns NULL rather than wrapping. */
void *buf_alloc(struct nss_buf *b, size_t n, size_t align)
{
    size_t pad;
    uintptr_t cur;
    void *p;

    if (align == 0)
        align = 1;

    cur = (uintptr_t)(b->base + b->off);
    pad = (size_t)((align - (size_t)(cur & (uintptr_t)(align - 1))) &
                   (align - 1));

    if (pad > b->len - b->off)
        return NULL;
    if (n > b->len - b->off - pad)
        return NULL;

    b->off += pad;
    p = b->base + b->off;
    b->off += n;
    return p;
}

/* Copy a NUL-terminated string into the buffer and return the copy. */
char *buf_strdup(struct nss_buf *b, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = buf_alloc(b, n, 1);

    if (p == NULL)
        return NULL;
    memcpy(p, s, n);
    return p;
}
