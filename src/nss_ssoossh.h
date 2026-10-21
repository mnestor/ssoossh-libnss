#ifndef SSOOSSH_NSS_SSOOSSH_H
#define SSOOSSH_NSS_SSOOSSH_H

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/types.h>
#include <stddef.h>

/* The NSS entry points glibc resolves from the module's dynamic symbol table.
 * They are marked default-visibility so they survive -fvisibility=hidden and
 * are exported; libnss_ssoossh.map lists the same set, and the two must agree.
 * Declaring them here also satisfies -Wmissing-prototypes, since glibc ships
 * no header for the module side of NSS. */
#define NSS_PUBLIC __attribute__((visibility("default")))

NSS_PUBLIC enum nss_status _nss_ssoossh_getpwnam_r(const char *name,
                                                   struct passwd *pwd,
                                                   char *buffer, size_t buflen,
                                                   int *errnop);

NSS_PUBLIC enum nss_status _nss_ssoossh_getpwuid_r(uid_t uid,
                                                   struct passwd *pwd,
                                                   char *buffer, size_t buflen,
                                                   int *errnop);

NSS_PUBLIC enum nss_status _nss_ssoossh_getgrnam_r(const char *name,
                                                   struct group *grp,
                                                   char *buffer, size_t buflen,
                                                   int *errnop);

NSS_PUBLIC enum nss_status _nss_ssoossh_getgrgid_r(gid_t gid, struct group *grp,
                                                   char *buffer, size_t buflen,
                                                   int *errnop);

NSS_PUBLIC enum nss_status _nss_ssoossh_getspnam_r(const char *name,
                                                   struct spwd *spwd,
                                                   char *buffer, size_t buflen,
                                                   int *errnop);

NSS_PUBLIC enum nss_status
_nss_ssoossh_initgroups_dyn(const char *user, gid_t group, long int *start,
                            long int *size, gid_t **groupsp, long int limit,
                            int *errnop);

#endif /* SSOOSSH_NSS_SSOOSSH_H */
