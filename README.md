# libnss_ssoossh

A glibc NSS module that resolves directory users and groups by asking the
local [`ssoossh-nss`](https://github.com/mnestor/ssoossh) daemon over its
systemd userdb varlink socket.

It exists for one reason: the RHEL 8 family (systemd 239) has no userdb client.
On systemd 245 and later, stock `nss-systemd` is the glibc side of
`ssoossh-nss` and this module is not needed and should not be installed. On the
EL8 floor, `nss-systemd` cannot speak userdb, so this module supplies the
missing client: it talks the same `io.systemd.UserDatabase` varlink protocol to
the same unchanged daemon. See issue
[mnestor/ssoossh#217](https://github.com/mnestor/ssoossh/issues/217).

**Status: all four NSS areas resolve; not yet released.** passwd (`getpwnam`,
`getpwuid`), group (`getgrnam`, `getgrgid`, with members from `GetMemberships`),
shadow (`getspnam`, a locked entry) and initgroups (`initgroups_dyn`) are wired
through the varlink client to the daemon. The build, the symbol/load/stdio/size
gates, the unit suites (buffer packer, JSON reader, record and group parsers,
config, varlink request/reply, gid list) and `make san` pass. Each entry
point's full path has been validated end to end against a stub over a real
socket, and the wire shapes were confirmed against live systemd 257. Still
open before a release: an in-tree, listener-backed integration test for the
socket transport (today it is covered out-of-tree and by `tools/varlink-probe.c`),
packaging (deb/rpm, SELinux policy, the release workflow), and a run against a
production `ssoossh-nss`.

## Why a module of our own, when that was declined

The ssoossh NSS directory serves hosts through systemd userdb precisely so
there is no NSS module of ours in callers (`ssoossh/.../project/decisions.md`,
"Declined: an NSS module of our own"). That decision stands for systemd 245+.
This module reopens it only for the EL8 floor, and narrowly: it is a backport
of `nss-systemd`'s userdb client, speaking systemd's own stable varlink
contract to the existing daemon. It is not the `nss_db` render route also
considered in #217, which would materialise the whole directory onto every
host and make it enumerable; this keeps the per-name, on-demand, non-enumerable
model userdb already has.

Costs accepted by reopening the decision, not wished away: our C runs inside
every setuid caller (`sudo`, `su`, `sshd`); there is a second (C) build
toolchain and a glibc NSS `.so` to maintain for EL8; and the userdb route's
open checks must be re-run on EL8.

## What it resolves

| nsswitch map | entry points |
| --- | --- |
| `passwd:` | `getpwnam_r`, `getpwuid_r` |
| `group:` | `getgrnam_r`, `getgrgid_r` |
| `shadow:` | `getspnam_r` (locked records only; never a usable hash) |
| `initgroups:` | `initgroups_dyn` |

`/etc/nsswitch.conf` gets the `ssoossh` token, e.g. `passwd: files ssoossh`.

**Non-enumerable on purpose.** The enumeration entry points
(`setpwent`/`getpwent`/`endpwent` and the group pair) are deliberately not
exported, so `getent passwd` with no name resolves nothing through this module.
That is the property that distinguishes it from an `nss_db` render of the
directory.

## Scope

glibc Linux only. NSS loadable modules are a glibc mechanism; musl has no
dlopen-based nsswitch, so a musl host cannot load this regardless. There is no
crypto and no HTTP in the module: it speaks to a root-owned local Unix socket,
and the daemon holds the fleet key and the TLS. That makes it far smaller than
the pam module it is modelled on (no libcrypto, libcurl or libpam link).

## Floor, verified

Confirmed on an AlmaLinux 8.10 host (2026-10-21):

- `glibc 2.28`, `systemd 239`. No `userdbctl`, no `/run/systemd/userdb`, no
  `systemd-userdbd` -- so on EL8 the daemon must create and listen on the
  socket itself; there is no socket activation to rely on (tracked in #217).
- `nss_db` is **not installed** by default here (contrary to an earlier note
  that it ships in BaseOS); it would be an added dependency. Moot for this
  module, which does not use it.
- A plain `AF_UNIX` + NUL-framed varlink round trip completes on glibc 2.28
  (the `tools/varlink-probe.c` check against a stand-in responder). The client
  path the module depends on works on the floor.

## Building

```console
$ make            # builds libnss_ssoossh.so.2
$ make test       # symbol gate, load gate, unit suite
$ make san        # the same, rebuilt with AddressSanitizer and UBSan
$ make check-stdio && make check-size
$ make lint       # clang-format, cppcheck, actionlint
$ make help
```

Build dependencies are only a C toolchain and glibc headers:

| Platform | Packages |
| --- | --- |
| RHEL 8+, AlmaLinux, Rocky | `gcc make glibc-devel` |
| Debian, Ubuntu | `build-essential` |

## The varlink probe

[`tools/varlink-probe.c`](tools/varlink-probe.c) is a standalone diagnostic,
not part of the module: an `AF_UNIX` varlink client that runs a single
`io.systemd.UserDatabase.GetUserRecord` call and prints the raw reply. It is
the quickest end-to-end smoke test once the daemon is listening on an EL8 host,
and it validates the exact request/reply shape against real systemd on a 245+
box:

```console
$ make probe
$ build/varlink-probe --socket /run/systemd/userdb/io.systemd.Multiplexer root
$ build/varlink-probe alice      # against ssoossh-nss, once it is listening
```

## Licence

MIT. See [LICENSE](LICENSE).
