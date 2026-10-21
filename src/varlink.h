/* The varlink client: one io.systemd.UserDatabase round trip to the daemon.
 *
 * A varlink message is a JSON object terminated by a NUL byte. A request names
 * a method and its parameters; a reply carries either {"parameters": {...}} or
 * {"error": "...", "parameters": {...}}. This module builds a single-key
 * request, exchanges it over the configured AF_UNIX socket within a bounded
 * deadline, and classifies the reply. It never blocks a caller indefinitely:
 * it lives inside sshd and sudo.
 */
#ifndef SSOOSSH_NSS_VARLINK_H
#define SSOOSSH_NSS_VARLINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"

#define VL_METHOD_GET_USER "io.systemd.UserDatabase.GetUserRecord"
#define VL_METHOD_GET_GROUP "io.systemd.UserDatabase.GetGroupRecord"
#define VL_METHOD_GET_MEMBERSHIPS "io.systemd.UserDatabase.GetMemberships"

/* Total deadline for a lookup (connect + write + read), in milliseconds. A
 * stuck daemon must not hang a login, so this is short. */
#define VL_TIMEOUT_MS 3000

/* Reply scratch size. A userdb record is a few hundred bytes; this is slack.
 * A reply larger than this is not ssoossh-nss and is treated as unavailable. */
#define VL_REPLY_MAX 8192

#define VL_REQUEST_MAX 1024

enum vl_status {
    VL_OK,        /* reply carried a record */
    VL_NOT_FOUND, /* daemon has no usable record; fall through to next source */
    VL_UNAVAIL,   /* transport failure, timeout, or malformed reply */
};

/* Builds a varlink request for `method` against cfg's service with a single
 * lookup key. Pass strval for a string key (userName/groupName -- caller-
 * supplied and therefore JSON-escaped) or numval for a numeric key (uid/gid);
 * exactly one must be non-NULL. Writes a NUL-terminated object into buf and
 * returns 0, or -1 if it would not fit or the key arguments are invalid.
 * Exposed for tests. */
int vl_build_request(char *buf, size_t cap, const char *method,
                     const char *service, const char *key, const char *strval,
                     const uint32_t *numval);

/* Classifies a raw varlink reply. On VL_OK, the record object inside reply is
 * returned through rec and rec_len (pointers into reply, not a copy) and the
 * incomplete flag through incomplete (when non-NULL). Accepts the record
 * either under "parameters" (the varlink wire form) or at the top level.
 * Exposed for tests. */
enum vl_status vl_parse_reply(const char *reply, size_t len, const char **rec,
                              size_t *rec_len, bool *incomplete);

/* One lookup round trip: build the request, connect to cfg->socket, exchange
 * within VL_TIMEOUT_MS, and classify. reply is caller-owned scratch of
 * reply_cap bytes (VL_REPLY_MAX) that must outlive any use of *rec. */
enum vl_status vl_lookup(const struct ssoossh_config *cfg, const char *method,
                         const char *key, const char *strval,
                         const uint32_t *numval, char *reply, size_t reply_cap,
                         const char **rec, size_t *rec_len, bool *incomplete);

/* Called once per membership. value/len is the requested field (a user name
 * when enumerating a group's members, a group name when enumerating a user's
 * groups), valid only for the duration of the call -- copy it. Return false to
 * stop the stream early (e.g. the result buffer filled). */
typedef bool (*vl_member_cb)(void *ctx, const char *value, size_t len);

/* Streams GetMemberships: query_key is "groupName" or "userName" and
 * query_value the name to match; want_field is the field to hand the callback
 * ("userName" for a group's members, "groupName" for a user's groups). Calls
 * cb per membership. Returns VL_OK when the stream completed (including an
 * empty set, and including an early stop requested by cb), or VL_UNAVAIL on a
 * transport failure, a truncated stream, or a malformed reply. */
enum vl_status vl_memberships(const struct ssoossh_config *cfg,
                              const char *query_key, const char *query_value,
                              const char *want_field, vl_member_cb cb,
                              void *ctx);

#endif /* SSOOSSH_NSS_VARLINK_H */
