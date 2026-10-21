/* The glibc NSS entry points for the "ssoossh" service.
 *
 * passwd lookups are wired through the varlink client to the ssoossh-nss
 * daemon: each entry point loads config, runs one GetUserRecord round trip,
 * and packs the returned record into the caller's NSS buffer. group, shadow
 * and initgroups are not wired yet and decline (NSS_STATUS_UNAVAIL), so a
 * lookup falls through to the next nsswitch source.
 *
 * NSS reentrancy contract: strings returned through `pwd` live in `buffer`
 * (src/buf.c), never on the heap; when they do not fit, the entry point sets
 * *errnop to ERANGE and returns NSS_STATUS_TRYAGAIN so the caller retries with
 * a larger buffer. */

#include "nss_ssoossh.h"

#include <errno.h>

#include "buf.h"
#include "config.h"
#include "record.h"
#include "varlink.h"

/* Maps a lookup result and parses the record into pwd. Shared by the name and
 * uid paths. */
static enum nss_status finish_user(enum vl_status status, const char *rec,
                                   size_t rec_len, struct passwd *pwd,
                                   char *buffer, size_t buflen, int *errnop)
{
    struct nss_buf b;
    int rc;

    switch (status) {
    case VL_OK:
        buf_init(&b, buffer, buflen);
        rc = record_user_to_passwd(rec, rec_len, pwd, &b, NULL);
        if (rc == ERANGE) {
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }
        if (rc != 0) {
            /* A record the daemon sent but we cannot use is, to the caller,
             * no record here. */
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    case VL_NOT_FOUND:
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    case VL_UNAVAIL:
    default:
        *errnop = EAGAIN;
        return NSS_STATUS_UNAVAIL;
    }
}

/* Resolve a user by name. */
enum nss_status _nss_ssoossh_getpwnam_r(const char *name, struct passwd *pwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    struct ssoossh_config cfg;
    char reply[VL_REPLY_MAX];
    const char *rec = NULL;
    size_t rec_len = 0;
    enum vl_status status;

    ssoossh_config_load(&cfg, NULL);
    status = vl_lookup(&cfg, VL_METHOD_GET_USER, "userName", name, NULL, reply,
                       sizeof(reply), &rec, &rec_len, NULL);
    return finish_user(status, rec, rec_len, pwd, buffer, buflen, errnop);
}

/* Resolve a user by uid. */
enum nss_status _nss_ssoossh_getpwuid_r(uid_t uid, struct passwd *pwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    struct ssoossh_config cfg;
    char reply[VL_REPLY_MAX];
    const char *rec = NULL;
    size_t rec_len = 0;
    uint32_t id = (uint32_t)uid;
    enum vl_status status;

    ssoossh_config_load(&cfg, NULL);
    status = vl_lookup(&cfg, VL_METHOD_GET_USER, "uid", NULL, &id, reply,
                       sizeof(reply), &rec, &rec_len, NULL);
    return finish_user(status, rec, rec_len, pwd, buffer, buflen, errnop);
}

/* Upper bound on members collected for one group, matching the daemon's own
 * nss.max_group_members ceiling. A larger group is truncated, as the daemon
 * truncates it. The pointers live in the NSS buffer; this array of pointers to
 * them is scratch on the stack during the lookup. */
#define MAX_GROUP_MEMBERS 2048

struct member_collector {
    struct nss_buf *buf;
    char *names[MAX_GROUP_MEMBERS];
    size_t count;
    bool erange;
};

/* Copies one member name into the NSS buffer and keeps its pointer. Stops the
 * stream (returns false) only when the buffer is full. */
static bool collect_member(void *ctx, const char *value, size_t len)
{
    struct member_collector *c = ctx;
    char *s;

    (void)len;
    if (c->count >= MAX_GROUP_MEMBERS) {
        return true; /* truncate like the daemon; keep draining the stream */
    }
    s = buf_strdup(c->buf, value);
    if (s == NULL) {
        c->erange = true;
        return false;
    }
    c->names[c->count++] = s;
    return true;
}

/* Streams the members of gname into grp->gr_mem, allocated in the NSS buffer.
 * grp must already carry name/passwd/gid. */
static enum nss_status fill_group_members(const struct ssoossh_config *cfg,
                                          const char *gname, struct group *grp,
                                          struct nss_buf *buf, int *errnop)
{
    struct member_collector c;
    enum vl_status s;
    char **arr;
    size_t i;

    c.buf = buf;
    c.count = 0;
    c.erange = false;

    s = vl_memberships(cfg, "groupName", gname, "userName", collect_member, &c);
    if (c.erange) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    /* Returning the group with a truncated-to-empty member list would be a
     * wrong answer a membership decision could turn on, so an unavailable
     * member stream fails the whole lookup. */
    if (s != VL_OK) {
        *errnop = EAGAIN;
        return NSS_STATUS_UNAVAIL;
    }

    arr = buf_alloc(buf, (c.count + 1) * sizeof(char *), sizeof(char *));
    if (arr == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    for (i = 0; i < c.count; i++) {
        arr[i] = c.names[i];
    }
    arr[c.count] = NULL;
    grp->gr_mem = arr;

    *errnop = 0;
    return NSS_STATUS_SUCCESS;
}

/* Maps a group-record lookup result and, on success, fills members. */
static enum nss_status finish_group(const struct ssoossh_config *cfg,
                                    enum vl_status status, const char *rec,
                                    size_t rec_len, struct group *grp,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct nss_buf b;
    int rc;

    switch (status) {
    case VL_OK:
        break;
    case VL_NOT_FOUND:
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    case VL_UNAVAIL:
    default:
        *errnop = EAGAIN;
        return NSS_STATUS_UNAVAIL;
    }

    buf_init(&b, buffer, buflen);
    rc = record_group_to_group(rec, rec_len, grp, &b);
    if (rc == ERANGE) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    if (rc != 0) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    return fill_group_members(cfg, grp->gr_name, grp, &b, errnop);
}

/* Resolve a group by name, with its member list. */
enum nss_status _nss_ssoossh_getgrnam_r(const char *name, struct group *grp,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    struct ssoossh_config cfg;
    char reply[VL_REPLY_MAX];
    const char *rec = NULL;
    size_t rec_len = 0;
    enum vl_status status;

    ssoossh_config_load(&cfg, NULL);
    status = vl_lookup(&cfg, VL_METHOD_GET_GROUP, "groupName", name, NULL,
                       reply, sizeof(reply), &rec, &rec_len, NULL);
    return finish_group(&cfg, status, rec, rec_len, grp, buffer, buflen,
                        errnop);
}

/* Resolve a group by gid, with its member list. */
enum nss_status _nss_ssoossh_getgrgid_r(gid_t gid, struct group *grp,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    struct ssoossh_config cfg;
    char reply[VL_REPLY_MAX];
    const char *rec = NULL;
    size_t rec_len = 0;
    uint32_t id = (uint32_t)gid;
    enum vl_status status;

    ssoossh_config_load(&cfg, NULL);
    status = vl_lookup(&cfg, VL_METHOD_GET_GROUP, "gid", NULL, &id, reply,
                       sizeof(reply), &rec, &rec_len, NULL);
    return finish_group(&cfg, status, rec, rec_len, grp, buffer, buflen,
                        errnop);
}

/* Resolve a shadow entry by name. The record carries the (locked) password
 * field only for a privileged peer; a usable hash never originates here. */
enum nss_status _nss_ssoossh_getspnam_r(const char *name, struct spwd *spwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    struct ssoossh_config cfg;
    char reply[VL_REPLY_MAX];
    const char *rec = NULL;
    size_t rec_len = 0;
    struct nss_buf b;
    enum vl_status status;
    int rc;

    ssoossh_config_load(&cfg, NULL);
    status = vl_lookup(&cfg, VL_METHOD_GET_USER, "userName", name, NULL, reply,
                       sizeof(reply), &rec, &rec_len, NULL);
    switch (status) {
    case VL_OK:
        break;
    case VL_NOT_FOUND:
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    case VL_UNAVAIL:
    default:
        *errnop = EAGAIN;
        return NSS_STATUS_UNAVAIL;
    }

    buf_init(&b, buffer, buflen);
    rc = record_user_to_spwd(rec, rec_len, spwd, &b);
    if (rc == ERANGE) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    if (rc != 0) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    *errnop = 0;
    return NSS_STATUS_SUCCESS;
}

/* Append the gids a user belongs to. Not wired yet. */
enum nss_status _nss_ssoossh_initgroups_dyn(const char *user, gid_t group,
                                            long int *start, long int *size,
                                            gid_t **groupsp, long int limit,
                                            int *errnop)
{
    (void)user;
    (void)group;
    (void)start;
    (void)size;
    (void)groupsp;
    (void)limit;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
}
