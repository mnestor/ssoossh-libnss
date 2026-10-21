/* The glibc NSS entry points for the "ssoossh" service.
 *
 * Each one is a thin front end that will: marshal a single
 * io.systemd.UserDatabase varlink call to the local ssoossh-nss daemon, parse
 * the JSON record it returns, and pack the result into the caller's fixed NSS
 * buffer. The varlink client (src/varlink.c) and the record parser
 * (src/record.c) are not landed yet, so every entry point currently declines
 * with NSS_STATUS_UNAVAIL. The build, symbol and load gates pass in this
 * state, and a real lookup falls through to the next nsswitch source rather
 * than resolving wrongly.
 *
 * NSS reentrancy contract, honoured once the bodies land: strings and arrays
 * returned through `pwd`/`grp`/`spwd` must live in `buffer` (see src/buf.c),
 * never on the heap; when they do not fit, the entry point sets *errnop to
 * ERANGE and returns NSS_STATUS_TRYAGAIN so the caller retries with a larger
 * buffer. */

#include "nss_ssoossh.h"

#include <errno.h>

/* Resolve a user by name. */
enum nss_status _nss_ssoossh_getpwnam_r(const char *name, struct passwd *pwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    (void)name;
    (void)pwd;
    (void)buffer;
    (void)buflen;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
}

/* Resolve a user by uid. */
enum nss_status _nss_ssoossh_getpwuid_r(uid_t uid, struct passwd *pwd,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    (void)uid;
    (void)pwd;
    (void)buffer;
    (void)buflen;
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
}

/* Resolve a group by name, with its member list. */
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

/* Resolve a group by gid, with its member list. */
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

/* Resolve a shadow entry by name. The daemon returns a locked record (sp_pwdp
 * "x" or "*", sp_expire set for disabled accounts); this never carries a
 * usable password hash. */
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

/* Append the gids a user belongs to, growing the caller's array as glibc's
 * initgroups_dyn contract requires. */
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
