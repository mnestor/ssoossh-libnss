/* Turning a systemd JSON User/Group record into the POSIX structs glibc wants.
 *
 * The daemon answers io.systemd.UserDatabase lookups with a record object; the
 * field names are systemd's (userName, uid, gid, realName, homeDirectory,
 * shell, locked), verified against systemd's USER_RECORD.md. These functions
 * read that object and pack the result into the caller's NSS buffer, returning
 * 0, or an errno the entry point hands back: EINVAL for a malformed or
 * incomplete record, ERANGE when the buffer is too small.
 */
#ifndef SSOOSSH_NSS_RECORD_H
#define SSOOSSH_NSS_RECORD_H

#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>

#include "buf.h"

/* Fills pwd from a user record object (the bytes of the record itself, not the
 * varlink envelope). userName, uid and gid are required; realName, home and
 * shell default to "", "/" and "" when absent. pw_passwd is always "x" -- the
 * hash never travels in this struct. When locked_out is non-NULL it receives
 * the record's "locked" flag (false when absent), which the shadow path needs.
 */
int record_user_to_passwd(const char *rec, size_t rec_len, struct passwd *pwd,
                          struct nss_buf *buf, bool *locked_out);

/* Fills grp from a group record object. groupName and gid are required.
 * gr_passwd is always "x", and gr_mem is left NULL: the member list is not in
 * the record (it comes from GetMemberships), so the caller fills it. Returns
 * 0, EINVAL for a malformed record, or ERANGE when the buffer is too small. */
int record_group_to_group(const char *rec, size_t rec_len, struct group *grp,
                          struct nss_buf *buf);

#endif /* SSOOSSH_NSS_RECORD_H */
