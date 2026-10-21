/* varlink-probe -- the one experiment that gates this whole module.
 *
 * It opens an AF_UNIX stream to a systemd userdb varlink socket and runs a
 * single io.systemd.UserDatabase.GetUserRecord call, by name or uid, printing
 * the raw reply. The question it answers, on an EL8 host where stock
 * nss-systemd has no userdb client: can a plain glibc client complete the
 * round trip against ssoossh-nss at all? If this prints a user record on
 * AlmaLinux 8, the module route is viable. If the connect or the exchange
 * fails, it is not, and no amount of module code fixes that.
 *
 * Standalone and dependency-free:
 *
 *   cc -std=c11 -O2 -Wall -Wextra -o varlink-probe tools/varlink-probe.c
 *   ./varlink-probe alice
 *   ./varlink-probe --uid 1000
 *   ./varlink-probe --socket /run/systemd/userdb/com.github.mnestor.ssoossh bob
 *
 * It is a diagnostic, not part of the shipped module, so printing to stdout is
 * correct here (the module's no-stdio rule covers src/ only).
 *
 * The varlink wire format is one JSON object per message terminated by a NUL
 * byte. A userdb query names the service it is addressed to in `parameters`;
 * when connecting straight to a single service's socket that is the service's
 * own name, which defaults here to the socket's basename. */
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/systemd/userdb/com.github.mnestor.ssoossh"
#define MAX_REPLY (1024 * 1024)

/* Write the whole buffer, retrying short writes. */
static int write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

/* Reject anything that would need JSON string escaping; this is a probe for
 * simple POSIX names, not a general client. */
static int name_is_simple(const char *s)
{
    for (; *s != '\0'; s++) {
        if (*s == '"' || *s == '\\' || (unsigned char)*s < 0x20)
            return 0;
    }
    return 1;
}

static const char *service_from_socket(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

int main(int argc, char **argv)
{
    const char *socket_path = DEFAULT_SOCKET;
    const char *service = NULL;
    const char *name = NULL;
    const char *uid = NULL;
    int i;
    int fd;
    struct sockaddr_un addr;
    char req[512];
    int reqlen;
    char reply[MAX_REPLY];
    size_t got = 0;
    int done = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--service") == 0 && i + 1 < argc) {
            service = argv[++i];
        } else if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            uid = argv[++i];
        } else if (argv[i][0] != '-') {
            name = argv[i];
        } else {
            fprintf(stderr,
                    "usage: %s [--socket PATH] [--service NAME] "
                    "(NAME | --uid UID)\n",
                    argv[0]);
            return 2;
        }
    }

    if ((name == NULL) == (uid == NULL)) {
        fprintf(stderr, "give exactly one of a user name or --uid\n");
        return 2;
    }
    if (name != NULL && !name_is_simple(name)) {
        fprintf(stderr, "probe only handles simple POSIX names\n");
        return 2;
    }
    if (service == NULL)
        service = service_from_socket(socket_path);

    if (uid != NULL) {
        char *end;
        unsigned long v = strtoul(uid, &end, 10);
        if (*uid == '\0' || *end != '\0' || v > UINT32_MAX) {
            fprintf(stderr, "bad --uid\n");
            return 2;
        }
        reqlen = snprintf(req, sizeof(req),
                          "{\"method\":\"io.systemd.UserDatabase."
                          "GetUserRecord\",\"parameters\":{\"service\":\"%s\","
                          "\"uid\":%lu}}",
                          service, v);
    } else {
        reqlen = snprintf(req, sizeof(req),
                          "{\"method\":\"io.systemd.UserDatabase."
                          "GetUserRecord\",\"parameters\":{\"service\":\"%s\","
                          "\"userName\":\"%s\"}}",
                          service, name);
    }
    if (reqlen < 0 || (size_t)reqlen >= sizeof(req)) {
        fprintf(stderr, "request too long\n");
        return 2;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long\n");
        close(fd);
        return 1;
    }
    strcpy(addr.sun_path, socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "connect %s: %s\n", socket_path, strerror(errno));
        close(fd);
        return 1;
    }

    /* The request plus its terminating NUL. */
    if (write_all(fd, req, (size_t)reqlen) < 0 || write_all(fd, "", 1) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    /* Read until the reply's terminating NUL or EOF. */
    while (got < sizeof(reply)) {
        ssize_t r = read(fd, reply + got, sizeof(reply) - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            close(fd);
            return 1;
        }
        if (r == 0)
            break;
        got += (size_t)r;
        if (memchr(reply + got - (size_t)r, '\0', (size_t)r) != NULL) {
            done = 1;
            break;
        }
    }
    close(fd);

    if (!done) {
        fprintf(stderr, "no NUL-terminated reply (%zu bytes read)\n", got);
        return 1;
    }

    printf("request:  %s\n", req);
    printf("reply:    %s\n", reply);
    return 0;
}
