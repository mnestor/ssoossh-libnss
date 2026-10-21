/* In-tree integration test for the socket transport (src/varlink.c): the parts
 * a unit test cannot reach without a live peer -- connect, the NUL-framed
 * reader, the streamed GetMemberships, and the failure paths. A forked child
 * serves canned varlink replies over a real AF_UNIX socket while the parent
 * drives vl_lookup / vl_memberships against it. Needs no privileges and no
 * network; run with `make integration`. Prints its result (tests/ is exempt
 * from the module's no-stdio rule). */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "buf.h"
#include "config.h"
#include "record.h"
#include "varlink.h"

static int failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL: %s\n", (msg));                                       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Writes msg plus its terminating NUL to a connected socket. */
static void send_msg(int fd, const char *msg)
{
    if (write(fd, msg, strlen(msg)) < 0 || write(fd, "", 1) < 0) {
        /* The parent will see a short/failed exchange and fail its check. */
    }
}

/* Serves one connection: reads the request, then replies based on what it
 * asks for. "silent" closes without replying, to exercise the EOF path. */
static void serve_one(int fd)
{
    char buf[4096];
    size_t n = 0;

    for (;;) {
        ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);

        if (r <= 0) {
            break;
        }
        n += (size_t)r;
        if (memchr(buf, '\0', n) != NULL || n >= sizeof(buf) - 1) {
            break;
        }
    }
    buf[n] = '\0';

    if (strstr(buf, "GetUserRecord") && strstr(buf, "\"userName\":\"alice\"")) {
        send_msg(fd, "{\"parameters\":{\"record\":{\"userName\":\"alice\","
                     "\"uid\":4242,\"gid\":4242,\"realName\":\"Alice\","
                     "\"homeDirectory\":\"/home/alice\",\"shell\":\"/bin/sh\"}"
                     ",\"incomplete\":false}}");
    } else if (strstr(buf, "\"userName\":\"ghost\"")) {
        send_msg(fd, "{\"error\":\"io.systemd.UserDatabase.NoRecordFound\","
                     "\"parameters\":{}}");
    } else if (strstr(buf, "\"userName\":\"silent\"")) {
        /* Reply with nothing, then close: the client should see EOF. */
    } else if (strstr(buf, "GetMemberships") &&
               strstr(buf, "\"groupName\":\"devs\"")) {
        send_msg(fd, "{\"parameters\":{\"userName\":\"alice\","
                     "\"groupName\":\"devs\"},\"continues\":true}");
        send_msg(fd, "{\"parameters\":{\"userName\":\"bob\","
                     "\"groupName\":\"devs\"}}");
    } else {
        send_msg(fd, "{\"error\":\"io.systemd.UserDatabase.NoRecordFound\","
                     "\"parameters\":{}}");
    }
    close(fd);
}

struct members {
    char seen[256];
    size_t count;
};

static bool on_member(void *ctx, const char *value, size_t len)
{
    struct members *m = ctx;

    (void)len;
    if (m->count != 0 && strlen(m->seen) + 2 < sizeof(m->seen)) {
        strcat(m->seen, ",");
    }
    if (strlen(m->seen) + strlen(value) + 1 < sizeof(m->seen)) {
        strcat(m->seen, value);
    }
    m->count++;
    return true;
}

int main(int argc, char **argv)
{
    const char *path;
    struct sockaddr_un addr;
    int lfd;
    pid_t pid;
    struct ssoossh_config cfg, bad;
    char reply[VL_REPLY_MAX];
    const char *rec;
    size_t rec_len;
    enum vl_status s;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <socket-path>\n", argv[0]);
        return 2;
    }
    path = argv[1];
    unlink(path);

    lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 2;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "path too long\n");
        return 2;
    }
    memcpy(addr.sun_path, path, strlen(path));
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(lfd, 8) < 0) {
        perror("bind/listen");
        return 2;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid == 0) {
        int i;

        for (i = 0; i < 4; i++) {
            int c = accept(lfd, NULL, NULL);

            if (c < 0) {
                break;
            }
            serve_one(c);
        }
        _exit(0);
    }
    close(lfd);

    ssoossh_config_defaults(&cfg);
    memcpy(cfg.socket, path, strlen(path) + 1);
    memcpy(cfg.service, "test", 5);

    /* 1. A user that resolves. */
    s = vl_lookup(&cfg, VL_METHOD_GET_USER, "userName", "alice", NULL, reply,
                  sizeof(reply), &rec, &rec_len, NULL);
    CHECK(s == VL_OK, "lookup alice: VL_OK");
    if (s == VL_OK) {
        char b[1024];
        struct nss_buf nb;
        struct passwd pw;

        buf_init(&nb, b, sizeof(b));
        CHECK(record_user_to_passwd(rec, rec_len, &pw, &nb, NULL) == 0 &&
                  strcmp(pw.pw_name, "alice") == 0 && pw.pw_uid == 4242,
              "lookup alice: record parsed");
    }

    /* 2. A user the daemon does not have. */
    s = vl_lookup(&cfg, VL_METHOD_GET_USER, "userName", "ghost", NULL, reply,
                  sizeof(reply), &rec, &rec_len, NULL);
    CHECK(s == VL_NOT_FOUND, "lookup ghost: VL_NOT_FOUND");

    /* 3. A membership stream. */
    {
        struct members m;

        m.seen[0] = '\0';
        m.count = 0;
        s = vl_memberships(&cfg, "groupName", "devs", "userName", on_member,
                           &m);
        CHECK(s == VL_OK, "memberships devs: VL_OK");
        CHECK(m.count == 2 && strcmp(m.seen, "alice,bob") == 0,
              "memberships devs: alice,bob");
    }

    /* 4. Nothing listening: connect fails. */
    ssoossh_config_defaults(&bad);
    memcpy(bad.service, "test", 5);
    snprintf(bad.socket, sizeof(bad.socket), "%s.none", path);
    s = vl_lookup(&bad, VL_METHOD_GET_USER, "userName", "alice", NULL, reply,
                  sizeof(reply), &rec, &rec_len, NULL);
    CHECK(s == VL_UNAVAIL, "connect refused: VL_UNAVAIL");

    /* 5. The peer accepts but closes without replying. */
    s = vl_lookup(&cfg, VL_METHOD_GET_USER, "userName", "silent", NULL, reply,
                  sizeof(reply), &rec, &rec_len, NULL);
    CHECK(s == VL_UNAVAIL, "peer closed without reply: VL_UNAVAIL");

    waitpid(pid, NULL, 0);
    unlink(path);

    if (failures != 0) {
        printf("integration: %d failure(s)\n", failures);
        return 1;
    }
    printf("integration: ok\n");
    return 0;
}
