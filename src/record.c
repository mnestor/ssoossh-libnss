#include "record.h"

#include <errno.h>

#include "json.h"

/* The longest string field we copy out of a record. systemd caps names at 32
 * bytes; homeDirectory, shell and realName are paths and a GECOS line, all
 * comfortably under this. A field longer than this is treated as absent, which
 * for a required field is EINVAL and for an optional one falls to the default.
 */
#define FIELD_MAX 4096

/* Reads one string field into the NSS buffer. With a default, an absent or
 * oversized field falls back to it; without one (required), that is EINVAL.
 * ERANGE when the NSS buffer cannot hold the value. */
static int field_to_buf(const char *rec, size_t rec_len, const char *field,
                        const char *dflt, struct nss_buf *buf, char **out)
{
    char tmp[FIELD_MAX];

    if (json_string(rec, rec_len, NULL, NULL, field, tmp, sizeof(tmp))) {
        *out = buf_strdup(buf, tmp);
    } else if (dflt != NULL) {
        *out = buf_strdup(buf, dflt);
    } else {
        return EINVAL;
    }
    return *out != NULL ? 0 : ERANGE;
}

int record_user_to_passwd(const char *rec, size_t rec_len, struct passwd *pwd,
                          struct nss_buf *buf, bool *locked_out)
{
    uint32_t uid, gid;
    char *name, *gecos, *home, *shell, *passwd;
    bool locked = false;
    int rc;

    /* Required identity. Without these the record is unusable, so decline
     * rather than invent a value. */
    if (!json_u32(rec, rec_len, NULL, NULL, "uid", &uid) ||
        !json_u32(rec, rec_len, NULL, NULL, "gid", &gid)) {
        return EINVAL;
    }
    if ((rc = field_to_buf(rec, rec_len, "userName", NULL, buf, &name)) != 0) {
        return rc;
    }

    /* Optional, with POSIX-safe defaults. */
    if ((rc = field_to_buf(rec, rec_len, "realName", "", buf, &gecos)) != 0) {
        return rc;
    }
    if ((rc = field_to_buf(rec, rec_len, "homeDirectory", "/", buf, &home)) !=
        0) {
        return rc;
    }
    if ((rc = field_to_buf(rec, rec_len, "shell", "", buf, &shell)) != 0) {
        return rc;
    }

    /* pw_passwd is always "x": the shadow path carries the (locked) hash, and
     * it is never a real one here. */
    passwd = buf_strdup(buf, "x");
    if (passwd == NULL) {
        return ERANGE;
    }

    (void)json_bool(rec, rec_len, NULL, NULL, "locked", &locked);

    pwd->pw_name = name;
    pwd->pw_passwd = passwd;
    pwd->pw_uid = (uid_t)uid;
    pwd->pw_gid = (gid_t)gid;
    pwd->pw_gecos = gecos;
    pwd->pw_dir = home;
    pwd->pw_shell = shell;

    if (locked_out != NULL) {
        *locked_out = locked;
    }
    return 0;
}
