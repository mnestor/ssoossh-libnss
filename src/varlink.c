#include "varlink.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "json.h"

/* --- request building (pure, unit-tested) --- */

/* Appends s, returning false if it does not fit. */
static bool put(char **p, char *end, const char *s)
{
    size_t n = strlen(s);

    if ((size_t)(end - *p) < n) {
        return false;
    }
    memcpy(*p, s, n);
    *p += n;
    return true;
}

/* Appends s as the inside of a JSON string, escaping what JSON requires. The
 * lookup name comes from the NSS caller, so this is the boundary that keeps a
 * crafted name from breaking out of the request object. */
static bool put_escaped(char **p, char *end, const char *s)
{
    static const char hex[] = "0123456789abcdef";

    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        char tmp[6];
        size_t n;

        if (c == '"' || c == '\\') {
            tmp[0] = '\\';
            tmp[1] = (char)c;
            n = 2;
        } else if (c < 0x20) {
            tmp[0] = '\\';
            tmp[1] = 'u';
            tmp[2] = '0';
            tmp[3] = '0';
            tmp[4] = hex[c >> 4];
            tmp[5] = hex[c & 0xf];
            n = 6;
        } else {
            tmp[0] = (char)c;
            n = 1;
        }
        if ((size_t)(end - *p) < n) {
            return false;
        }
        memcpy(*p, tmp, n);
        *p += n;
    }
    return true;
}

/* Appends a uint32 in decimal. */
static bool put_u32(char **p, char *end, uint32_t v)
{
    char tmp[10];
    int i = (int)sizeof(tmp);
    size_t n;

    do {
        tmp[--i] = (char)('0' + (v % 10));
        v /= 10;
    } while (v != 0);

    n = sizeof(tmp) - (size_t)i;
    if ((size_t)(end - *p) < n) {
        return false;
    }
    memcpy(*p, tmp + i, n);
    *p += n;
    return true;
}

int vl_build_request(char *buf, size_t cap, const char *method,
                     const char *service, const char *key, const char *strval,
                     const uint32_t *numval)
{
    char *p = buf;
    char *end = buf + cap;

    /* Exactly one key kind. */
    if ((strval == NULL) == (numval == NULL)) {
        return -1;
    }

    if (!put(&p, end, "{\"method\":\"") || !put(&p, end, method) ||
        !put(&p, end, "\",\"parameters\":{\"service\":\"") ||
        !put_escaped(&p, end, service) || !put(&p, end, "\",\"") ||
        !put(&p, end, key) || !put(&p, end, "\":")) {
        return -1;
    }

    if (strval != NULL) {
        if (!put(&p, end, "\"") || !put_escaped(&p, end, strval) ||
            !put(&p, end, "\"")) {
            return -1;
        }
    } else {
        if (!put_u32(&p, end, *numval)) {
            return -1;
        }
    }

    if (!put(&p, end, "}}")) {
        return -1;
    }
    if ((size_t)(end - p) < 1) {
        return -1;
    }
    *p = '\0';
    return 0;
}

/* --- reply classification (pure, unit-tested) --- */

enum vl_status vl_parse_reply(const char *reply, size_t len, const char **rec,
                              size_t *rec_len, bool *incomplete)
{
    char err[128];
    bool inc = false;

    *rec = NULL;
    *rec_len = 0;
    if (incomplete != NULL) {
        *incomplete = false;
    }
    if (len == 0) {
        return VL_UNAVAIL;
    }

    /* An error reply: {"error":"io.systemd.UserDatabase.<Name>", ...}. The
     * daemon-level "no usable record" errors fall through as not-found (U3:
     * unavailable reaches callers as not found); anything else is a transport
     * or protocol problem. */
    if (json_string(reply, len, NULL, NULL, "error", err, sizeof(err))) {
        if (strstr(err, "NoRecordFound") != NULL ||
            strstr(err, "ConflictingRecordFound") != NULL ||
            strstr(err, "NonMatchingRecordFound") != NULL ||
            strstr(err, "ServiceNotAvailable") != NULL) {
            return VL_NOT_FOUND;
        }
        return VL_UNAVAIL;
    }

    /* A success reply carries the record under "parameters" on the wire;
     * accept it at the top level too, since varlinkctl prints it unwrapped and
     * the exact shape a given peer sends is not worth a surprise. */
    if (json_object_span(reply, len, "parameters", NULL, "record", rec,
                         rec_len) ||
        json_object_span(reply, len, NULL, NULL, "record", rec, rec_len)) {
        if (json_bool(reply, len, "parameters", NULL, "incomplete", &inc) ||
            json_bool(reply, len, NULL, NULL, "incomplete", &inc)) {
            /* found either way */
        }
        if (incomplete != NULL) {
            *incomplete = inc;
        }
        return VL_OK;
    }

    return VL_UNAVAIL;
}

/* --- socket transport ---
 *
 * Not unit-tested here: these need a live peer on an AF_UNIX socket. They are
 * exercised end to end by tools/varlink-probe.c against a stub and against the
 * daemon; an in-tree integration test with a background listener is a
 * worklist item. The pure halves above (request build, reply parse) carry the
 * logic that a unit test can reach. */

/* Milliseconds on the monotonic clock. */
static long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Waits for `events` on fd until the deadline. Returns 1 when ready, 0 on
 * timeout or error. */
static int poll_until(int fd, short events, long deadline)
{
    for (;;) {
        long rem = deadline - now_ms();
        struct pollfd pfd;
        int r;

        if (rem <= 0) {
            return 0;
        }
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;
        r = poll(&pfd, 1, (int)(rem > INT_MAX ? INT_MAX : rem));
        if (r > 0) {
            return 1;
        }
        if (r == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        return 0;
    }
}

/* Connects a non-blocking AF_UNIX stream to path, bounded by the deadline.
 * Returns the fd or -1. */
static int connect_dl(const char *path, long deadline)
{
    struct sockaddr_un addr;
    int fd, err = 0;
    socklen_t elen = sizeof(err);

    if (strlen(path) >= sizeof(addr.sun_path)) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (!poll_until(fd, POLLOUT, deadline)) {
        close(fd);
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Writes the whole buffer within the deadline. Returns 0 or -1. */
static int write_all_dl(int fd, const char *buf, size_t len, long deadline)
{
    size_t off = 0;

    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);

        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!poll_until(fd, POLLOUT, deadline)) {
                return -1;
            }
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

/* Reads until the reply's terminating NUL, the cap, or the deadline. On
 * success returns 1 and sets *out to the NUL's index (the JSON length). */
static int read_reply_dl(int fd, char *buf, size_t cap, size_t *out,
                         long deadline)
{
    size_t got = 0;

    while (got < cap) {
        ssize_t r = read(fd, buf + got, cap - got);

        if (r > 0) {
            void *nul = memchr(buf + got, '\0', (size_t)r);

            got += (size_t)r;
            if (nul != NULL) {
                *out = (size_t)((char *)nul - buf);
                return 1;
            }
            continue;
        }
        if (r == 0) {
            return 0; /* EOF before a NUL */
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!poll_until(fd, POLLIN, deadline)) {
                return 0;
            }
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        return 0;
    }
    return 0; /* cap reached without a NUL: not our daemon */
}

enum vl_status vl_lookup(const struct ssoossh_config *cfg, const char *method,
                         const char *key, const char *strval,
                         const uint32_t *numval, char *reply, size_t reply_cap,
                         const char **rec, size_t *rec_len, bool *incomplete)
{
    char req[VL_REQUEST_MAX];
    long deadline;
    int fd;
    size_t rlen = 0;

    *rec = NULL;
    *rec_len = 0;
    if (incomplete != NULL) {
        *incomplete = false;
    }

    /* A request that will not form (e.g. a name longer than the buffer) can
     * never match a real entry, so treat it as not-found rather than an
     * error. */
    if (vl_build_request(req, sizeof(req), method, cfg->service, key, strval,
                         numval) != 0) {
        return VL_NOT_FOUND;
    }

    deadline = now_ms() + VL_TIMEOUT_MS;
    fd = connect_dl(cfg->socket, deadline);
    if (fd < 0) {
        return VL_UNAVAIL;
    }

    /* The request object and its terminating NUL. */
    if (write_all_dl(fd, req, strlen(req), deadline) != 0 ||
        write_all_dl(fd, "", 1, deadline) != 0) {
        close(fd);
        return VL_UNAVAIL;
    }

    if (read_reply_dl(fd, reply, reply_cap, &rlen, deadline) != 1) {
        close(fd);
        return VL_UNAVAIL;
    }
    close(fd);

    return vl_parse_reply(reply, rlen, rec, rec_len, incomplete);
}
