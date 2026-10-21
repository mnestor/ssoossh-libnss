/* Reading fields out of the JSON the ssoossh-nss daemon sends over varlink.
 *
 * Deliberately not a decoder: nothing is allocated and no object graph is
 * built. jsmn tokenises into a fixed array of offsets on the stack, and each
 * accessor re-parses and hands back one value -- a string unescaped into the
 * caller's buffer, an integer, a bool, or the byte span of a sub-object. A
 * malformed reply therefore has no structure of ours to corrupt, and the body
 * is capped before any of it runs.
 *
 * Every accessor takes up to two parent object names so a nested field can be
 * read without first extracting its container: a varlink reply
 * {"parameters":{"record":{...}}} is read with o1="parameters", o2="record".
 * Pass NULL for parents that do not apply.
 */
#ifndef SSOOSSH_NSS_JSON_H
#define SSOOSSH_NSS_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The daemon's replies are small; this is a hard stop for anything claiming
 * otherwise, which is not ssoossh-nss answering. */
#define JSON_MAX_BODY (64 * 1024)

/* Reads o1.o2.field as a string, unescaping it into out (always
 * NUL-terminated on success). Returns false when the body is not a JSON
 * object, a named parent is missing or not an object, the field is absent,
 * not a string, or does not fit in out. */
bool json_string(const char *body, size_t len, const char *o1, const char *o2,
                 const char *field, char *out, size_t out_cap);

/* Reads o1.o2.field as an unsigned 32-bit integer. Returns false when it is
 * absent, not a number, negative, or out of range. */
bool json_u32(const char *body, size_t len, const char *o1, const char *o2,
              const char *field, uint32_t *out);

/* Reads o1.o2.field as a boolean. Returns false when it is absent or not a
 * JSON true/false. */
bool json_bool(const char *body, size_t len, const char *o1, const char *o2,
               const char *field, bool *out);

/* Locates o1.o2.field as an object and returns its byte span inside body
 * (pointers into body, not a copy). Returns false when it is absent or not an
 * object. Used to hand a nested record to the record parser without copying. */
bool json_object_span(const char *body, size_t len, const char *o1,
                      const char *o2, const char *field, const char **obj,
                      size_t *obj_len);

/* Reads the first element of the array o1.o2.field as a string, unescaping it
 * into out. Returns 1 when present (out filled), 0 when the array is present
 * but empty or its first element is not a usable string, and -1 when the field
 * is absent or not an array. Used for privileged.hashedPassword, where present
 * vs empty vs absent each map to a different shadow password field. */
int json_array_first_string(const char *body, size_t len, const char *o1,
                            const char *o2, const char *field, char *out,
                            size_t out_cap);

#endif /* SSOOSSH_NSS_JSON_H */
