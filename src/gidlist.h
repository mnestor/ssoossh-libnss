/* The gid-array growth that glibc's initgroups_dyn contract puts on the
 * module: *groupsp holds *start gids of *size capacity and may be realloc'd to
 * grow. Kept separate from the entry point so the sizing and dedup -- where an
 * off-by-one is a heap bug -- can be unit-tested on their own. */
#ifndef SSOOSSH_NSS_GIDLIST_H
#define SSOOSSH_NSS_GIDLIST_H

#include <sys/types.h>

/* Appends gid, growing *groupsp if full (doubling, capped by a positive
 * limit). Skips a gid already present and one that would exceed a positive
 * limit. Returns 0 on append, 1 when skipped, -1 on allocation failure (the
 * array is left intact). A non-positive limit means no limit. */
int gidlist_add(gid_t **groupsp, long *start, long *size, long limit,
                gid_t gid);

#endif /* SSOOSSH_NSS_GIDLIST_H */
