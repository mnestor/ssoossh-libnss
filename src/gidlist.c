#include "gidlist.h"

#include <stdlib.h>

int gidlist_add(gid_t **groupsp, long *start, long *size, long limit, gid_t gid)
{
    long i;

    /* Already present: glibc expects the module to dedup its own additions. */
    for (i = 0; i < *start; i++) {
        if ((*groupsp)[i] == gid) {
            return 1;
        }
    }
    if (limit > 0 && *start >= limit) {
        return 1;
    }

    if (*start >= *size) {
        long next = (*size > 0) ? *size * 2 : 16;
        gid_t *grown;

        if (limit > 0 && next > limit) {
            next = limit;
        }
        if (next <= *start) {
            next = *start + 1;
        }
        grown = realloc(*groupsp, (size_t)next * sizeof(gid_t));
        if (grown == NULL) {
            return -1;
        }
        *groupsp = grown;
        *size = next;
    }

    (*groupsp)[(*start)++] = gid;
    return 0;
}
