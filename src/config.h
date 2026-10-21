/* Where to reach the daemon: the userdb varlink socket and the service name
 * sent in each request.
 *
 * The defaults are the fixed systemd userdb socket path and the product's
 * reverse-DNS service id, correct on a normal install with nothing set. An
 * admin overrides them in a root-owned /etc/ssoossh/nss.conf. There is no
 * environment variable and no nsswitch argument: NSS has no call-line
 * arguments, and an environment value cannot be both admin-settable and
 * trustworthy inside a setuid caller (sudo, su), which is where this module
 * also runs. A root-owned file is the only source that is both.
 */
#ifndef SSOOSSH_NSS_CONFIG_H
#define SSOOSSH_NSS_CONFIG_H

#include <stddef.h>

#define SSOOSSH_NSS_DEFAULT_SOCKET                                             \
    "/run/systemd/userdb/com.github.mnestor.ssoossh"
#define SSOOSSH_NSS_DEFAULT_SERVICE "com.github.mnestor.ssoossh"
#define SSOOSSH_NSS_CONFIG_PATH "/etc/ssoossh/nss.conf"

/* A Unix socket path is kernel-capped near 108 bytes; a service name is a
 * reverse-DNS label. Fixed and generous, so the config holds no allocation. */
#define SSOOSSH_NSS_SOCKET_MAX 108
#define SSOOSSH_NSS_SERVICE_MAX 256

struct ssoossh_config {
    char socket[SSOOSSH_NSS_SOCKET_MAX];
    char service[SSOOSSH_NSS_SERVICE_MAX];
};

/* Sets cfg to the built-in defaults. */
void ssoossh_config_defaults(struct ssoossh_config *cfg);

/* Applies key=value overrides from an in-memory buffer onto an
 * already-defaulted cfg. Recognised keys: socket, service. Blank lines and
 * lines whose first non-space character is '#' are ignored, as are unknown
 * keys, lines with no '=', and values that are empty or too long for their
 * field (the default stays). Leading and trailing spaces, tabs and a trailing
 * CR are trimmed from keys and values. Exposed for tests; the file path is
 * read by ssoossh_config_load. */
void ssoossh_config_apply(struct ssoossh_config *cfg, const char *text,
                          size_t len);

/* Loads config: defaults, then the key=value file at path (NULL means
 * SSOOSSH_NSS_CONFIG_PATH) applied over them. A missing or unreadable file is
 * not an error -- the defaults stand. cfg is always left fully populated. */
void ssoossh_config_load(struct ssoossh_config *cfg, const char *path);

#endif /* SSOOSSH_NSS_CONFIG_H */
