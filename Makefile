# libnss_ssoossh -- a glibc NSS module that resolves directory users and
# groups by asking the local ssoossh-nss daemon over its systemd userdb
# varlink socket. It exists for hosts below systemd 245 (the RHEL 8 family),
# where stock nss-systemd has no userdb client; everywhere 245+ nss-systemd is
# that client and this module is not needed.
#
# glibc/Linux only: NSS loadable modules are a glibc mechanism and load
# nowhere else. There is no macOS, FreeBSD or musl build, and no crypto or
# HTTP -- the module speaks to a root-owned local socket, and the daemon holds
# the fleet key and the TLS.

UNAME := $(shell uname -s)
ARCH  := $(shell uname -m)

ifneq ($(UNAME),Linux)
  $(error libnss_ssoossh is glibc/Linux only; NSS modules load nowhere else)
endif

# glibc looks for an NSS module named libnss_<service>.so.2 beside libc, so the
# service token in nsswitch.conf is "ssoossh" (passwd: files ssoossh).
MODULE := libnss_ssoossh.so.2
BUILD  := build

# Version is stamped in at build time rather than tracked in a header, so a
# working tree and a release build report differently on purpose.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The ssoossh-nss release this module was last qualified against. The module
# and the daemon are versioned independently, so this is the compatibility
# fact a fleet needs; bumping it is the deliberate act of re-running the
# integration suite against a newer daemon.
SSOOSSH_NSS_COMPAT ?= v0.0.0

# NSS module install directory: beside libc, discovered not assumed (Debian
# multiarch vs the RHEL family's lib64 vs usr-merge symlinks), the first that
# exists on the installing machine. Override with `make install NSSDIR=...`.
NSSDIR ?= $(firstword $(wildcard \
    /lib/$(ARCH)-linux-gnu \
    /usr/lib/$(ARCH)-linux-gnu \
    /lib64 \
    /usr/lib64 \
    /lib \
    /usr/lib))

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))

# Sanitiser flags reach both the module link and the test binaries; under the
# sanitisers --no-undefined comes off, because clang leaves the ASan runtime
# to the loading process and the symbols are undefined in a -shared link.
SANCFLAGS  :=
SANLDFLAGS :=
NOUNDEF    := -Wl,--no-undefined
ifeq ($(SAN),1)
  SANCFLAGS  := -fsanitize=address,undefined -fno-omit-frame-pointer -O1
  SANLDFLAGS := -fsanitize=address,undefined
  CFLAGS     += $(SANCFLAGS)
  LDFLAGS    += $(SANLDFLAGS)
  NOUNDEF    :=
else
  # Fortify only outside the sanitiser build: ASan predefines _FORTIFY_SOURCE 0
  # and redefining it is a -Werror macro-redefinition.
  FORTIFY := -D_FORTIFY_SOURCE=2
endif

CFLAGS += -std=c11 -O2 -fPIC \
          -fvisibility=hidden \
          -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith \
          -Wstrict-prototypes -Wmissing-prototypes -Werror \
          -fstack-protector-strong -fstack-clash-protection \
          $(FORTIFY) \
          -D_GNU_SOURCE \
          -DNSS_SSOOSSH_VERSION='"$(VERSION)"' \
          -DNSS_SSOOSSH_COMPAT='"$(SSOOSSH_NSS_COMPAT)"'
CPPFLAGS += -Isrc

# Same hardening as the pam module: relro/now, non-exec stack, the version
# script, and --no-undefined so a missing symbol fails the link here rather
# than at dlopen inside sshd.
LDFLAGS += -shared \
           -Wl,-soname,$(MODULE) \
           $(NOUNDEF) \
           -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
           -Wl,--version-script=libnss_ssoossh.map

STRIP      ?= strip --strip-unneeded
SIZE_LIMIT ?= 262144

.PHONY: all clean test check-symbols check-stdio check-size san lint install \
        probe help

all: $(MODULE)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(MODULE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# The module must export exactly the six NSS entry points. Anything else -- a
# helper named parse(), a vendored json symbol -- is a name that can collide
# inside a process that resolves users.
check-symbols: $(MODULE)
	@set -e; \
	got=$$(nm -D --defined-only $(MODULE) | awk '$$2 ~ /^[TDBR]$$/ {print $$3}' | sort); \
	want=$$(printf '%s\n' \
	    _nss_ssoossh_getgrgid_r _nss_ssoossh_getgrnam_r \
	    _nss_ssoossh_getpwnam_r _nss_ssoossh_getpwuid_r \
	    _nss_ssoossh_getspnam_r _nss_ssoossh_initgroups_dyn | sort); \
	if [ "$$got" != "$$want" ]; then \
	  echo "check-symbols: exported symbols are not the expected six:"; \
	  echo "$$got" | sed 's/^/  /'; \
	  exit 1; \
	fi; \
	echo "check-symbols: ok"

# Nothing in the module may write to stdout or stderr: it is dlopened into
# sshd, sudo, cron and every other name-resolving process, where both streams
# belong to the host. tests/ and tools/ are exempt and are not scanned.
check-stdio:
	@if grep -nE '\b(printf|fprintf|puts|putchar|perror|vprintf|vfprintf)\s*\(|\bwrite\s*\(\s*[12]\s*,' \
	     src/*.c src/*.h; then \
	  echo "check-stdio: the module must not write to stdout or stderr"; \
	  exit 1; \
	fi; \
	echo "check-stdio: ok"

# A stripped module over this usually means something got statically linked
# that should not have been.
check-size: $(MODULE)
	@cp $(MODULE) $(BUILD)/stripped.so && $(STRIP) $(BUILD)/stripped.so; \
	size=$$(wc -c < $(BUILD)/stripped.so); \
	echo "check-size: $$size bytes stripped (limit $(SIZE_LIMIT))"; \
	if [ "$$size" -gt "$(SIZE_LIMIT)" ]; then \
	  echo "check-size: over the limit"; exit 1; \
	fi

# Proves the module loads through the dynamic loader and exposes exactly the
# NSS entry points. Needs -ldl on the EL8 floor (glibc 2.28, pre-2.34 merge).
tests/loadtest: tests/loadtest.c
	$(CC) -std=c11 -O1 -Wall -Wextra -Werror $(SANCFLAGS) $(SANLDFLAGS) \
	    -o $@ $< -ldl

# The unit suite links the module's own objects rather than recompiling them,
# so what the tests exercise is the code that ships. Hidden visibility is no
# obstacle inside a single executable.
UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_OBJ := $(patsubst tests/unit/%.c,$(BUILD)/unit/%.o,$(UNIT_SRC))

$(BUILD)/unit:
	@mkdir -p $(BUILD)/unit

$(BUILD)/unit/%.o: tests/unit/%.c | $(BUILD)/unit
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

tests/unit_tests: $(OBJ) $(UNIT_OBJ)
	$(CC) $(SANLDFLAGS) -o $@ $^ $(LDLIBS)

test: check-symbols tests/loadtest tests/unit_tests
	@./tests/loadtest ./$(MODULE)
	@./tests/unit_tests

# make SAN=1 turns the sanitisers on for everything built in the invocation,
# the unit suite included; `make san` is that plus the clean rebuild the
# changed flags require.
san:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SAN=1 all test

# The EL8 round-trip probe (tools/varlink-probe.c): a standalone AF_UNIX
# varlink client, no module, for settling whether a plain glibc client can
# complete a userdb lookup against ssoossh-nss on the floor. Not shipped.
probe: tools/varlink-probe.c
	$(CC) -std=c11 -O2 -Wall -Wextra -o $(BUILD)/varlink-probe $< && \
	  echo "probe: built $(BUILD)/varlink-probe"

# Every tool here is best-effort: a missing one is skipped, not fatal, so a
# partial lint is more use than an error about a tool the caller lacks.
lint:
	@rc=0; \
	for t in clang-format cppcheck actionlint; do \
	  command -v $$t >/dev/null || { echo "lint: $$t not installed, skipping"; continue; }; \
	  case $$t in \
	    clang-format) clang-format --dry-run --Werror \
	                    src/*.c src/*.h tests/*.c tests/unit/*.c tools/*.c || rc=1 ;; \
	    cppcheck)     cppcheck --quiet --error-exitcode=1 \
	                    --enable=warning,portability \
	                    --suppress=missingIncludeSystem -Isrc src tests tools || rc=1 ;; \
	    actionlint)   actionlint || rc=1 ;; \
	  esac; \
	done; \
	[ $$rc -eq 0 ] && echo "lint: ok"; exit $$rc

install: $(MODULE)
	@test -n "$(NSSDIR)" || { \
	  echo "install: no NSS module dir found; pass NSSDIR=<dir>" >&2; exit 1; }
	install -d $(DESTDIR)$(NSSDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(NSSDIR)/$(MODULE)
	@echo "installed $(DESTDIR)$(NSSDIR)/$(MODULE)"
	@echo "add 'ssoossh' to passwd:, group:, shadow: and initgroups: in /etc/nsswitch.conf"

clean:
	rm -rf $(BUILD) $(MODULE) tests/loadtest tests/unit_tests

help:
	@echo "make            build $(MODULE)"
	@echo "make test       symbol gate, load gate, and the unit suite"
	@echo "make san        rebuild under ASan/UBSan and re-test"
	@echo "make check-stdio  assert the module writes to neither stdout nor stderr"
	@echo "make check-size   assert the stripped module is under $(SIZE_LIMIT) bytes"
	@echo "make probe      build the standalone EL8 varlink round-trip probe"
	@echo "make lint       clang-format, cppcheck, actionlint"
	@echo "make install    install into $(if $(NSSDIR),$(NSSDIR),<none found>)"
	@echo ""
	@echo "VERSION=$(VERSION)"
	@echo "SSOOSSH_NSS_COMPAT=$(SSOOSSH_NSS_COMPAT)  the daemon release this build was qualified against"
