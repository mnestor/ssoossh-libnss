/* Unit tests for the varlink request builder and reply classifier
 * (src/varlink.c). The socket transport is not reached here -- it needs a live
 * peer -- but the pure halves carry the logic worth pinning: exact request
 * bytes, name escaping, and the mapping from reply shapes to vl_status. */
#include "test.h"

#include <stdint.h>
#include <string.h>

#include "json.h"
#include "varlink.h"

/* should build a GetUserRecord request keyed by name */
static void test_build_by_name(void)
{
    char buf[256];
    int rc = vl_build_request(buf, sizeof(buf), VL_METHOD_GET_USER, "svc",
                              "userName", "alice", NULL);
    const char *want =
        "{\"method\":\"io.systemd.UserDatabase.GetUserRecord\","
        "\"parameters\":{\"service\":\"svc\",\"userName\":\"alice\"}}";

    CHECK(rc == 0, "build name: returns 0");
    CHECK(rc == 0 && strcmp(buf, want) == 0, "build name: exact bytes");
}

/* should build a request keyed by a numeric id */
static void test_build_by_id(void)
{
    char buf[256];
    uint32_t id = 1000;
    int rc = vl_build_request(buf, sizeof(buf), VL_METHOD_GET_USER, "svc",
                              "uid", NULL, &id);
    const char *want = "{\"method\":\"io.systemd.UserDatabase.GetUserRecord\","
                       "\"parameters\":{\"service\":\"svc\",\"uid\":1000}}";

    CHECK(rc == 0 && strcmp(buf, want) == 0, "build id: exact bytes");
}

/* should JSON-escape a caller-supplied name */
static void test_build_escapes_name(void)
{
    char buf[256];
    int rc = vl_build_request(buf, sizeof(buf), VL_METHOD_GET_USER, "svc",
                              "userName", "a\"b\\c", NULL);

    CHECK(rc == 0 && strstr(buf, "\"userName\":\"a\\\"b\\\\c\"") != NULL,
          "build escape: quote and backslash escaped");
}

/* should fail when the buffer is too small, and on bad key arguments */
static void test_build_errors(void)
{
    char small[16];
    char buf[256];
    uint32_t id = 1;

    CHECK(vl_build_request(small, sizeof(small), VL_METHOD_GET_USER, "svc",
                           "userName", "alice", NULL) == -1,
          "build: overflow returns -1");
    CHECK(vl_build_request(buf, sizeof(buf), VL_METHOD_GET_USER, "svc", "uid",
                           "alice", &id) == -1,
          "build: both key kinds is -1");
    CHECK(vl_build_request(buf, sizeof(buf), VL_METHOD_GET_USER, "svc", "uid",
                           NULL, NULL) == -1,
          "build: neither key kind is -1");
}

/* should classify a success reply and expose the record span */
static void test_parse_success(void)
{
    const char *reply = "{\"parameters\":{\"record\":{\"userName\":\"x\","
                        "\"uid\":1,\"gid\":1},\"incomplete\":false}}";
    const char *rec = NULL;
    size_t rec_len = 0;
    bool incomplete = true;
    enum vl_status s =
        vl_parse_reply(reply, strlen(reply), &rec, &rec_len, &incomplete);
    char name[8];

    CHECK(s == VL_OK, "parse success: VL_OK");
    CHECK(incomplete == false, "parse success: incomplete false");
    CHECK(s == VL_OK &&
              json_string(rec, rec_len, NULL, NULL, "userName", name,
                          sizeof(name)) &&
              strcmp(name, "x") == 0,
          "parse success: record span is the record object");
}

/* should accept a record at the top level (varlinkctl's unwrapped shape) */
static void test_parse_top_level_record(void)
{
    const char *reply = "{\"record\":{\"userName\":\"y\",\"uid\":1,\"gid\":1}}";
    const char *rec = NULL;
    size_t rec_len = 0;
    enum vl_status s =
        vl_parse_reply(reply, strlen(reply), &rec, &rec_len, NULL);

    CHECK(s == VL_OK, "parse top-level: VL_OK");
}

/* should map the daemon's no-record errors to not-found */
static void test_parse_notfound_errors(void)
{
    const char *not_found =
        "{\"error\":\"io.systemd.UserDatabase.NoRecordFound\","
        "\"parameters\":{}}";
    const char *busy =
        "{\"error\":\"io.systemd.UserDatabase.ServiceNotAvailable\","
        "\"parameters\":{}}";
    const char *rec;
    size_t rec_len;

    CHECK(vl_parse_reply(not_found, strlen(not_found), &rec, &rec_len, NULL) ==
              VL_NOT_FOUND,
          "parse: NoRecordFound -> NOT_FOUND");
    CHECK(vl_parse_reply(busy, strlen(busy), &rec, &rec_len, NULL) ==
              VL_NOT_FOUND,
          "parse: ServiceNotAvailable -> NOT_FOUND");
}

/* should map other errors and malformed replies to unavailable */
static void test_parse_unavail(void)
{
    const char *bad_service =
        "{\"error\":\"io.systemd.UserDatabase.BadService\","
        "\"parameters\":{}}";
    const char *malformed = "{\"parameters\":{}}";
    const char *rec;
    size_t rec_len;

    CHECK(vl_parse_reply(bad_service, strlen(bad_service), &rec, &rec_len,
                         NULL) == VL_UNAVAIL,
          "parse: BadService -> UNAVAIL");
    CHECK(vl_parse_reply(malformed, strlen(malformed), &rec, &rec_len, NULL) ==
              VL_UNAVAIL,
          "parse: no record and no error -> UNAVAIL");
    CHECK(vl_parse_reply("", 0, &rec, &rec_len, NULL) == VL_UNAVAIL,
          "parse: empty -> UNAVAIL");
}

/* should report incomplete:true through the flag */
static void test_parse_incomplete(void)
{
    const char *reply = "{\"parameters\":{\"record\":{\"groupName\":\"wheel\","
                        "\"gid\":10},\"incomplete\":true}}";
    const char *rec;
    size_t rec_len;
    bool incomplete = false;

    CHECK(vl_parse_reply(reply, strlen(reply), &rec, &rec_len, &incomplete) ==
              VL_OK,
          "parse incomplete: VL_OK");
    CHECK(incomplete == true, "parse incomplete: flag true");
}

void varlink_tests(void)
{
    test_build_by_name();
    test_build_by_id();
    test_build_escapes_name();
    test_build_errors();
    test_parse_success();
    test_parse_top_level_record();
    test_parse_notfound_errors();
    test_parse_unavail();
    test_parse_incomplete();
}
