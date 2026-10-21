/* Unit tests for the userdb record parser (src/record.c) and the JSON reader
 * it sits on (src/json.c). Daemon-independent: fixtures are the exact record
 * shape from systemd's USER_RECORD.md, so these pin the field names and the
 * envelope unwrap without a running ssoossh-nss. */
#include "test.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "buf.h"
#include "json.h"
#include "record.h"

/* The example user record from systemd's USER_RECORD.md, as the daemon's
 * "record" object. */
#define REC_GROBIE                                                             \
    "{\"userName\":\"grobie\",\"uid\":60232,\"gid\":60232,"                    \
    "\"realName\":\"Example User\",\"homeDirectory\":\"/home/grobie\","        \
    "\"shell\":\"/bin/bash\",\"locked\":false,"                                \
    "\"privileged\":{\"hashedPassword\":[\"$6$salt$hash\"]}}"

/* should map every passwd field from a complete record */
static void test_full_record(void)
{
    char raw[256];
    struct nss_buf b;
    struct passwd pw;
    bool locked = true;
    int rc;

    buf_init(&b, raw, sizeof(raw));
    rc =
        record_user_to_passwd(REC_GROBIE, strlen(REC_GROBIE), &pw, &b, &locked);
    CHECK(rc == 0, "full: returns 0");
    CHECK(rc == 0 && strcmp(pw.pw_name, "grobie") == 0, "full: pw_name");
    CHECK(rc == 0 && pw.pw_uid == 60232, "full: pw_uid");
    CHECK(rc == 0 && pw.pw_gid == 60232, "full: pw_gid");
    CHECK(rc == 0 && strcmp(pw.pw_gecos, "Example User") == 0, "full: gecos");
    CHECK(rc == 0 && strcmp(pw.pw_dir, "/home/grobie") == 0, "full: home");
    CHECK(rc == 0 && strcmp(pw.pw_shell, "/bin/bash") == 0, "full: shell");
    CHECK(rc == 0 && strcmp(pw.pw_passwd, "x") == 0, "full: pw_passwd is x");
    CHECK(rc == 0 && locked == false, "full: locked false");
}

/* should decline a record missing a required identity field */
static void test_missing_uid(void)
{
    const char *rec = "{\"userName\":\"u\",\"gid\":1,\"homeDirectory\":\"/h\"}";
    char raw[128];
    struct nss_buf b;
    struct passwd pw;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_passwd(rec, strlen(rec), &pw, &b, NULL) == EINVAL,
          "missing uid: EINVAL");
}

/* should return ERANGE when the result buffer cannot hold the strings */
static void test_buffer_too_small(void)
{
    char raw[8];
    struct nss_buf b;
    struct passwd pw;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_passwd(REC_GROBIE, strlen(REC_GROBIE), &pw, &b,
                                NULL) == ERANGE,
          "small buffer: ERANGE");
}

/* should report a locked account through locked_out */
static void test_locked(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5,"
                      "\"homeDirectory\":\"/h\",\"shell\":\"/s\","
                      "\"locked\":true}";
    char raw[128];
    struct nss_buf b;
    struct passwd pw;
    bool locked = false;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_passwd(rec, strlen(rec), &pw, &b, &locked) == 0,
          "locked: parses");
    CHECK(locked == true, "locked: flag true");
}

/* should default optional fields when absent */
static void test_defaults(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5}";
    char raw[128];
    struct nss_buf b;
    struct passwd pw;
    int rc;

    buf_init(&b, raw, sizeof(raw));
    rc = record_user_to_passwd(rec, strlen(rec), &pw, &b, NULL);
    CHECK(rc == 0, "defaults: parses");
    CHECK(rc == 0 && strcmp(pw.pw_gecos, "") == 0, "defaults: empty gecos");
    CHECK(rc == 0 && strcmp(pw.pw_dir, "/") == 0, "defaults: home /");
    CHECK(rc == 0 && strcmp(pw.pw_shell, "") == 0, "defaults: empty shell");
}

/* should unescape a JSON string value */
static void test_escaping(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5,"
                      "\"realName\":\"a\\\"b\\\\c\"}";
    char raw[128];
    struct nss_buf b;
    struct passwd pw;
    int rc;

    buf_init(&b, raw, sizeof(raw));
    rc = record_user_to_passwd(rec, strlen(rec), &pw, &b, NULL);
    CHECK(rc == 0 && strcmp(pw.pw_gecos, "a\"b\\c") == 0,
          "escaping: realName unescaped");
}

/* should unwrap a record nested in a varlink reply envelope */
static void test_envelope_unwrap(void)
{
    const char *reply =
        "{\"parameters\":{\"record\":" REC_GROBIE ",\"incomplete\":false}}";
    const char *rec;
    size_t rec_len;
    char raw[256];
    struct nss_buf b;
    struct passwd pw;

    CHECK(json_object_span(reply, strlen(reply), "parameters", NULL, "record",
                           &rec, &rec_len),
          "envelope: record object located");
    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_passwd(rec, rec_len, &pw, &b, NULL) == 0 &&
              strcmp(pw.pw_name, "grobie") == 0,
          "envelope: parses the unwrapped record");
}

/* should type-check: a string where a number is expected, and vice versa */
static void test_type_mismatch(void)
{
    uint32_t u;
    char out[32];

    CHECK(!json_u32(REC_GROBIE, strlen(REC_GROBIE), NULL, NULL, "userName", &u),
          "types: u32 on a string value fails");
    CHECK(!json_string(REC_GROBIE, strlen(REC_GROBIE), NULL, NULL, "uid", out,
                       sizeof(out)),
          "types: string on a number value fails");
}

/* should map groupName and gid, with gr_mem left for the caller */
static void test_group_record(void)
{
    const char *rec = "{\"groupName\":\"devs\",\"gid\":4000,"
                      "\"privileged\":{\"hashedPassword\":[\"\"]}}";
    char raw[128];
    struct nss_buf b;
    struct group gr;
    int rc;

    buf_init(&b, raw, sizeof(raw));
    rc = record_group_to_group(rec, strlen(rec), &gr, &b);
    CHECK(rc == 0, "group: returns 0");
    CHECK(rc == 0 && strcmp(gr.gr_name, "devs") == 0, "group: gr_name");
    CHECK(rc == 0 && gr.gr_gid == 4000, "group: gr_gid");
    CHECK(rc == 0 && strcmp(gr.gr_passwd, "x") == 0, "group: gr_passwd is x");
    CHECK(rc == 0 && gr.gr_mem == NULL, "group: gr_mem left NULL");
}

/* should decline a group record missing gid or groupName */
static void test_group_missing(void)
{
    const char *no_gid = "{\"groupName\":\"devs\"}";
    const char *no_name = "{\"gid\":4000}";
    char raw[128];
    struct nss_buf b;
    struct group gr;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_group_to_group(no_gid, strlen(no_gid), &gr, &b) == EINVAL,
          "group: missing gid is EINVAL");
    buf_init(&b, raw, sizeof(raw));
    CHECK(record_group_to_group(no_name, strlen(no_name), &gr, &b) == EINVAL,
          "group: missing groupName is EINVAL");
}

/* should return ERANGE when the group name does not fit */
static void test_group_buffer_too_small(void)
{
    const char *rec = "{\"groupName\":\"devs\",\"gid\":4000}";
    char raw[2];
    struct nss_buf b;
    struct group gr;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_group_to_group(rec, strlen(rec), &gr, &b) == ERANGE,
          "group: small buffer is ERANGE");
}

/* should take sp_pwdp from a present hashedPassword and leave the account open
 */
static void test_shadow_active(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5,"
                      "\"privileged\":{\"hashedPassword\":[\"*\"]}}";
    char raw[128];
    struct nss_buf b;
    struct spwd sp;
    int rc;

    buf_init(&b, raw, sizeof(raw));
    rc = record_user_to_spwd(rec, strlen(rec), &sp, &b);
    CHECK(rc == 0, "shadow active: parses");
    CHECK(rc == 0 && strcmp(sp.sp_namp, "u") == 0, "shadow active: sp_namp");
    CHECK(rc == 0 && strcmp(sp.sp_pwdp, "*") == 0, "shadow active: sp_pwdp *");
    CHECK(rc == 0 && sp.sp_expire == -1, "shadow active: sp_expire unset");
    CHECK(rc == 0 && sp.sp_lstchg == -1, "shadow active: sp_lstchg unset");
}

/* should map an empty hashedPassword to a locked field */
static void test_shadow_empty_hash(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5,"
                      "\"privileged\":{\"hashedPassword\":[]}}";
    char raw[128];
    struct nss_buf b;
    struct spwd sp;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_spwd(rec, strlen(rec), &sp, &b) == 0 &&
              strcmp(sp.sp_pwdp, "!*") == 0,
          "shadow empty hash: sp_pwdp !*");
}

/* should map an absent privileged section (non-root peer) to "*" */
static void test_shadow_no_privileged(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5}";
    char raw[128];
    struct nss_buf b;
    struct spwd sp;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_spwd(rec, strlen(rec), &sp, &b) == 0 &&
              strcmp(sp.sp_pwdp, "*") == 0,
          "shadow no privileged: sp_pwdp *");
}

/* should set sp_expire when the record is locked */
static void test_shadow_locked(void)
{
    const char *rec = "{\"userName\":\"u\",\"uid\":5,\"gid\":5,"
                      "\"locked\":true}";
    char raw[128];
    struct nss_buf b;
    struct spwd sp;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_spwd(rec, strlen(rec), &sp, &b) == 0 &&
              sp.sp_expire == 1,
          "shadow locked: sp_expire 1");
}

/* should decline a record with no userName */
static void test_shadow_missing_name(void)
{
    const char *rec = "{\"uid\":5,\"gid\":5}";
    char raw[128];
    struct nss_buf b;
    struct spwd sp;

    buf_init(&b, raw, sizeof(raw));
    CHECK(record_user_to_spwd(rec, strlen(rec), &sp, &b) == EINVAL,
          "shadow missing name: EINVAL");
}

void record_tests(void)
{
    test_full_record();
    test_missing_uid();
    test_buffer_too_small();
    test_locked();
    test_defaults();
    test_escaping();
    test_envelope_unwrap();
    test_type_mismatch();
    test_group_record();
    test_group_missing();
    test_group_buffer_too_small();
    test_shadow_active();
    test_shadow_empty_hash();
    test_shadow_no_privileged();
    test_shadow_locked();
    test_shadow_missing_name();
}
