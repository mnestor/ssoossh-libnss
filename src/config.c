#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* Copies src into dst[cap], truncating if it somehow would not fit. The
 * defaults always fit; this is defensive. */
static void copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void ssoossh_config_defaults(struct ssoossh_config *cfg)
{
    copy_str(cfg->socket, sizeof(cfg->socket), SSOOSSH_NSS_DEFAULT_SOCKET);
    copy_str(cfg->service, sizeof(cfg->service), SSOOSSH_NSS_DEFAULT_SERVICE);
}

/* Trims leading/trailing spaces and tabs, and a trailing CR, in place by
 * moving the start and end pointers. */
static void trim(const char **ps, const char **pe)
{
    const char *s = *ps;
    const char *e = *pe;

    while (s < e && (*s == ' ' || *s == '\t')) {
        s++;
    }
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) {
        e--;
    }
    *ps = s;
    *pe = e;
}

/* Sets a field from a trimmed value span, keeping the default when the value
 * is empty or too long. */
static void set_field(char *dst, size_t cap, const char *vs, const char *ve)
{
    size_t n = (size_t)(ve - vs);

    if (n == 0 || n >= cap) {
        return;
    }
    memcpy(dst, vs, n);
    dst[n] = '\0';
}

/* Processes one line span [s, e). */
static void apply_line(struct ssoossh_config *cfg, const char *s, const char *e)
{
    const char *eq, *ks, *ke, *vs, *ve;
    size_t klen;

    trim(&s, &e);
    if (s == e || *s == '#') {
        return;
    }
    eq = memchr(s, '=', (size_t)(e - s));
    if (eq == NULL) {
        return;
    }

    ks = s;
    ke = eq;
    trim(&ks, &ke);
    vs = eq + 1;
    ve = e;
    trim(&vs, &ve);

    klen = (size_t)(ke - ks);
    if (klen == strlen("socket") && memcmp(ks, "socket", klen) == 0) {
        set_field(cfg->socket, sizeof(cfg->socket), vs, ve);
    } else if (klen == strlen("service") && memcmp(ks, "service", klen) == 0) {
        set_field(cfg->service, sizeof(cfg->service), vs, ve);
    }
    /* Unknown keys are ignored, so a newer config on an older module is not a
     * hard error. */
}

void ssoossh_config_apply(struct ssoossh_config *cfg, const char *text,
                          size_t len)
{
    size_t i = 0;

    while (i < len) {
        size_t j = i;

        while (j < len && text[j] != '\n') {
            j++;
        }
        apply_line(cfg, text + i, text + j);
        i = (j < len) ? j + 1 : j;
    }
}

void ssoossh_config_load(struct ssoossh_config *cfg, const char *path)
{
    char buf[8192];
    size_t total = 0;
    int fd;

    ssoossh_config_defaults(cfg);

    if (path == NULL) {
        path = SSOOSSH_NSS_CONFIG_PATH;
    }
    /* O_CLOEXEC so the descriptor cannot leak into a child of the process that
     * happened to do the lookup. A missing file leaves the defaults. */
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }

    while (total < sizeof(buf)) {
        ssize_t r = read(fd, buf + total, sizeof(buf) - total);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; /* a read error leaves whatever defaults/overrides so far */
        }
        if (r == 0) {
            break;
        }
        total += (size_t)r;
    }
    close(fd);

    ssoossh_config_apply(cfg, buf, total);
}
