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

/* Resolve a group by name, with its member list. Not wired yet. */
enum nss_status _nss_ssoossh_getgrnam_r(const char *name, struct group *grp,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    (void)name;
    (void)grp;
    (void)buffer;
    (void)buflen;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
}

/* Resolve a group by gid, with its member list. Not wired yet. */
enum nss_status _nss_ssoossh_getgrgid_r(gid_t gid, struct group *grp,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    (void)gid;
    (void)grp;
    (void)buffer;
    (void)buflen;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
}

/* Resolve a shadow entry by name. Not wired yet. */
enum nss_status _nss_ssoossh_getspnam_r(const char *name, struct spwd *spwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    (void)name;
    (void)spwd;
    (void)buffer;
    (void)buflen;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
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
