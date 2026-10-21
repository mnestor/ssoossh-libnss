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

/* Writes {"method":"<method>",[<"more":true,">]"parameters":{"service":
 * "<service>","<key>":<value>}} into buf, NUL-terminated. value is strval
 * (escaped string) or *numval. Returns 0 or -1 on overflow / bad arguments. */
static int build(char *buf, size_t cap, const char *method, bool more,
                 const char *service, const char *key, const char *strval,
                 const uint32_t *numval)
{
    char *p = buf;
    char *end = buf + cap;

    if ((strval == NULL) == (numval == NULL)) {
        return -1;
    }
    if (!put(&p, end, "{\"method\":\"") || !put(&p, end, method) ||
        !put(&p, end, "\",") || (more && !put(&p, end, "\"more\":true,")) ||
        !put(&p, end, "\"parameters\":{\"service\":\"") ||
        !put_escaped(&p, end, service) || !put(&p, end, "\",\"") ||
        !put(&p, end, key) || !put(&p, end, "\":")) {
        return -1;
    }
    if (strval != NULL) {
        if (!put(&p, end, "\"") || !put_escaped(&p, end, strval) ||
            !put(&p, end, "\"")) {
            return -1;
        }
    } else if (!put_u32(&p, end, *numval)) {
        return -1;
    }
    if (!put(&p, end, "}}") || (size_t)(end - p) < 1) {
        return -1;
    }
    *p = '\0';
    return 0;
}

int vl_build_request(char *buf, size_t cap, const char *method,
                     const char *service, const char *key, const char *strval,
                     const uint32_t *numval)
{
    return build(buf, cap, method, false, service, key, strval, numval);
}

/* --- reply classification (pure, unit-tested) --- */

/* True when err names a daemon-level "no usable record" condition, which the
 * caller treats as not-found rather than a hard failure (U3). */
static bool err_is_not_found(const char *err)
{
    return strstr(err, "NoRecordFound") != NULL ||
           strstr(err, "ConflictingRecordFound") != NULL ||
           strstr(err, "NonMatchingRecordFound") != NULL ||
           strstr(err, "ServiceNotAvailable") != NULL;
}

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

    if (json_string(reply, len, NULL, NULL, "error", err, sizeof(err))) {
        return err_is_not_found(err) ? VL_NOT_FOUND : VL_UNAVAIL;
    }

    /* A success reply carries the record under "parameters" on the wire;
     * accept it at the top level too, since varlinkctl prints it unwrapped. */
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
 * exercised end to end by tools/varlink-probe.c and by an out-of-tree stub
 * check; an in-tree listener-backed integration test is a worklist item. The
 * pure halves above carry the logic a unit test can reach. */

/* Milliseconds on the monotonic clock. */
static long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Waits for `events` on fd until the deadline. 1 when ready, 0 otherwise. */
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

/* A NUL-framed message reader over a caller-provided buffer, so several
 * replies (GetMemberships streams them) can be read from one connection. */
struct vl_reader {
    int fd;
    long deadline;
    char *buf;
    size_t cap;
    size_t len; /* bytes held in buf */
    size_t pos; /* next unconsumed byte */
};

/* Returns the next NUL-terminated message (msg/msglen exclude the NUL,
 * pointing into the reader's buffer): 1 on a message, 0 at a clean end (EOF
 * with no partial awaited), -1 on timeout, error, or an over-long message. */
static int vl_next(struct vl_reader *r, const char **msg, size_t *msglen)
{
    for (;;) {
        if (r->pos < r->len) {
            void *nul = memchr(r->buf + r->pos, '\0', r->len - r->pos);

            if (nul != NULL) {
                *msg = r->buf + r->pos;
                *msglen = (size_t)((char *)nul - (r->buf + r->pos));
                r->pos = (size_t)((char *)nul - r->buf) + 1;
                return 1;
            }
        }
        /* No complete message buffered: compact and read more. */
        if (r->pos > 0) {
            memmove(r->buf, r->buf + r->pos, r->len - r->pos);
            r->len -= r->pos;
            r->pos = 0;
        }
        if (r->len == r->cap) {
            return -1; /* a message larger than the buffer: not our daemon */
        }
        {
            ssize_t rr = read(r->fd, r->buf + r->len, r->cap - r->len);

            if (rr > 0) {
                r->len += (size_t)rr;
                continue;
            }
            if (rr == 0) {
                return 0; /* EOF */
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!poll_until(r->fd, POLLIN, r->deadline)) {
                    return -1;
                }
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
}

/* Connects and sends req (plus its terminating NUL). Returns the fd or -1. */
static int send_request(const char *socket_path, const char *req, long deadline)
{
    int fd = connect_dl(socket_path, deadline);

    if (fd < 0) {
        return -1;
    }
    if (write_all_dl(fd, req, strlen(req), deadline) != 0 ||
        write_all_dl(fd, "", 1, deadline) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

enum vl_status vl_lookup(const struct ssoossh_config *cfg, const char *method,
                         const char *key, const char *strval,
                         const uint32_t *numval, char *reply, size_t reply_cap,
                         const char **rec, size_t *rec_len, bool *incomplete)
{
    char req[VL_REQUEST_MAX];
    struct vl_reader r;
    const char *msg;
    size_t msglen;
    long deadline;
    int fd, n;

    *rec = NULL;
    *rec_len = 0;
    if (incomplete != NULL) {
        *incomplete = false;
    }

    /* A request that will not form (e.g. a name longer than the buffer) can
     * never match a real entry, so treat it as not-found. */
    if (vl_build_request(req, sizeof(req), method, cfg->service, key, strval,
                         numval) != 0) {
        return VL_NOT_FOUND;
    }

    deadline = now_ms() + VL_TIMEOUT_MS;
    fd = send_request(cfg->socket, req, deadline);
    if (fd < 0) {
        return VL_UNAVAIL;
    }

    r.fd = fd;
    r.deadline = deadline;
    r.buf = reply;
    r.cap = reply_cap;
    r.len = 0;
    r.pos = 0;
    n = vl_next(&r, &msg, &msglen);
    close(fd);
    if (n != 1) {
        return VL_UNAVAIL;
    }
    return vl_parse_reply(msg, msglen, rec, rec_len, incomplete);
}

enum vl_status vl_memberships(const struct ssoossh_config *cfg,
                              const char *query_key, const char *query_value,
                              const char *want_field, vl_member_cb cb,
                              void *ctx)
{
    char req[VL_REQUEST_MAX];
    char scratch[VL_REPLY_MAX];
    struct vl_reader r;
    long deadline;
    int fd;
    enum vl_status result = VL_OK;
    bool expect_more = true;

    if (build(req, sizeof(req), VL_METHOD_GET_MEMBERSHIPS, true, cfg->service,
              query_key, query_value, NULL) != 0) {
        return VL_NOT_FOUND;
    }

    deadline = now_ms() + VL_TIMEOUT_MS;
    fd = send_request(cfg->socket, req, deadline);
    if (fd < 0) {
        return VL_UNAVAIL;
    }

    r.fd = fd;
    r.deadline = deadline;
    r.buf = scratch;
    r.cap = sizeof(scratch);
    r.len = 0;
    r.pos = 0;

    for (;;) {
        const char *msg;
        size_t msglen;
        char err[128];
        char value[128];
        bool cont = false;
        int n = vl_next(&r, &msg, &msglen);

        if (n == 0) {
            /* A clean end while a continuation was still promised is a
             * truncated stream, not an empty set. */
            result = expect_more ? VL_UNAVAIL : VL_OK;
            break;
        }
        if (n < 0) {
            result = VL_UNAVAIL;
            break;
        }

        if (json_string(msg, msglen, NULL, NULL, "error", err, sizeof(err))) {
            /* No memberships is reported as a not-found error: an empty set,
             * not a failure. */
            result = err_is_not_found(err) ? VL_OK : VL_UNAVAIL;
            break;
        }

        if ((json_string(msg, msglen, "parameters", NULL, want_field, value,
                         sizeof(value)) ||
             json_string(msg, msglen, NULL, NULL, want_field, value,
                         sizeof(value))) &&
            !cb(ctx, value, strlen(value))) {
            result = VL_OK; /* caller asked to stop */
            break;
        }

        if (json_bool(msg, msglen, NULL, NULL, "continues", &cont) && cont) {
            expect_more = true;
            continue;
        }
        expect_more = false;
        result = VL_OK;
        break;
    }

    close(fd);
    return result;
}
