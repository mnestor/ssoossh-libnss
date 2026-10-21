/* Unit tests for the config reader (src/config.c). Exercised through the
 * buffer parser so no file is touched; the file wrapper is a thin open/read
 * around it. */
#include "test.h"

#include <string.h>

#include "config.h"

static void load_str(struct ssoossh_config *c, const char *s)
{
    ssoossh_config_defaults(c);
    ssoossh_config_apply(c, s, strlen(s));
}

/* should start from the built-in defaults */
static void test_defaults(void)
{
    struct ssoossh_config c;

    ssoossh_config_defaults(&c);
    CHECK(strcmp(c.socket, SSOOSSH_NSS_DEFAULT_SOCKET) == 0,
          "defaults: socket");
    CHECK(strcmp(c.service, SSOOSSH_NSS_DEFAULT_SERVICE) == 0,
          "defaults: service");
}

/* should apply socket and service overrides, trimming surrounding space */
static void test_override(void)
{
    struct ssoossh_config c;

    load_str(&c, "socket = /run/x\nservice =\tmy.svc\n");
    CHECK(strcmp(c.socket, "/run/x") == 0, "override: socket trimmed");
    CHECK(strcmp(c.service, "my.svc") == 0, "override: service trimmed");
}

/* should ignore blank lines and #-comments, indented or not */
static void test_comments_blanks(void)
{
    struct ssoossh_config c;

    load_str(&c, "# a comment\n\n   \n  # indented\nsocket=/y\n");
    CHECK(strcmp(c.socket, "/y") == 0, "comments: socket set");
    CHECK(strcmp(c.service, SSOOSSH_NSS_DEFAULT_SERVICE) == 0,
          "comments: service still default");
}

/* should ignore an unknown key and keep processing */
static void test_unknown_key(void)
{
    struct ssoossh_config c;

    load_str(&c, "foo=bar\nsocket=/z\n");
    CHECK(strcmp(c.socket, "/z") == 0, "unknown: later key applied");
    CHECK(strcmp(c.service, SSOOSSH_NSS_DEFAULT_SERVICE) == 0,
          "unknown: ignored");
}

/* should ignore a line with no '=' */
static void test_no_equals(void)
{
    struct ssoossh_config c;

    load_str(&c, "socketnonsense\nsocket=/w\n");
    CHECK(strcmp(c.socket, "/w") == 0, "no '=': line skipped, next applied");
}

/* should keep the default when a value is too long for its field */
static void test_value_too_long(void)
{
    struct ssoossh_config c;
    char line[SSOOSSH_NSS_SOCKET_MAX + 32];

    memcpy(line, "socket=", 7);
    memset(line + 7, 'a', SSOOSSH_NSS_SOCKET_MAX + 10);
    line[7 + SSOOSSH_NSS_SOCKET_MAX + 10] = '\0';
    load_str(&c, line);
    CHECK(strcmp(c.socket, SSOOSSH_NSS_DEFAULT_SOCKET) == 0,
          "too long: default kept");
}

/* should parse a final line with no trailing newline */
static void test_no_trailing_newline(void)
{
    struct ssoossh_config c;

    load_str(&c, "socket=/nl");
    CHECK(strcmp(c.socket, "/nl") == 0, "no trailing newline parsed");
}

/* should trim a trailing CR from a CRLF file */
static void test_crlf(void)
{
    struct ssoossh_config c;

    load_str(&c, "socket=/cr\r\n");
    CHECK(strcmp(c.socket, "/cr") == 0, "crlf: CR trimmed");
}

/* should keep the default for an empty value but still apply other keys */
static void test_empty_value(void)
{
    struct ssoossh_config c;

    load_str(&c, "socket=\nservice=keep.me\n");
    CHECK(strcmp(c.socket, SSOOSSH_NSS_DEFAULT_SOCKET) == 0,
          "empty value: default kept");
    CHECK(strcmp(c.service, "keep.me") == 0,
          "empty value: other key still applied");
}

void config_tests(void)
{
    test_defaults();
    test_override();
    test_comments_blanks();
    test_unknown_key();
    test_no_equals();
    test_value_too_long();
    test_no_trailing_newline();
    test_crlf();
    test_empty_value();
}
