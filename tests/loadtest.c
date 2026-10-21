/* Proves the built module loads through the dynamic loader and exposes exactly
 * the NSS entry points glibc will look up -- the same check glibc itself does
 * at resolve time, run in isolation so a link or visibility regression shows
 * here rather than as a silent "user not found" on a host. Prints its result
 * to stdout on purpose: a test binary reporting pass or fail is the point, and
 * the module's no-stdio rule (make check-stdio) exempts tests/. */
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    static const char *const syms[] = {
        "_nss_ssoossh_getpwnam_r", "_nss_ssoossh_getpwuid_r",
        "_nss_ssoossh_getgrnam_r", "_nss_ssoossh_getgrgid_r",
        "_nss_ssoossh_getspnam_r", "_nss_ssoossh_initgroups_dyn",
    };
    size_t n = sizeof(syms) / sizeof(syms[0]);
    void *h;
    int rc = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <module.so>\n", argv[0]);
        return 2;
    }

    h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    for (size_t i = 0; i < n; i++) {
        void *p;

        dlerror();
        p = dlsym(h, syms[i]);
        if (p == NULL || dlerror() != NULL) {
            fprintf(stderr, "missing symbol: %s\n", syms[i]);
            rc = 1;
        }
    }

    dlclose(h);
    if (rc == 0)
        printf("loadtest: ok (%zu entry points)\n", n);
    return rc;
}
