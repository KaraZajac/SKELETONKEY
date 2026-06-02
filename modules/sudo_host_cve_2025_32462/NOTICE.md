# NOTICE — sudo_host (CVE-2025-32462)

## Vulnerability

**CVE-2025-32462** — sudo's `-h`/`--host` option, intended only to be
used with `-l`/`--list` to display a user's privileges on a *different*
host, was also honored when actually running a command (or via
`sudoedit`). This lets a user evaluate the sudoers policy as though the
machine were some other host: a sudoers rule scoped to a host that is
neither the current machine nor `ALL` becomes usable locally via
`sudo -h <that-host> <command>`, yielding command execution as root.

Primarily affects sites that distribute one sudoers file across a fleet,
or use LDAP/SSSD-based sudoers, where host-restricted rules are common.

- Affected: sudo **1.8.8** through **1.9.17p0** (the `-h` behaviour is
  ~12 years old). Fixed in **1.9.17p1**.
- CWE-863 (Incorrect Authorization). CVSS 8.8 (High). Not in CISA KEV
  (the sibling `--chroot` bug CVE-2025-32463 is).

## Research credit

Discovered and disclosed by **Rich Mirch — Stratascale Cyber Research
Unit (CRU)**, published 2025-06-30 alongside CVE-2025-32463.

- sudo.ws advisory: <https://www.sudo.ws/security/advisories/host_any/>
- Stratascale writeup:
  <https://www.stratascale.com/resource/cve-2025-32462-sudo-host-option-vulnerability/>
- Fixed in sudo 1.9.17p1 (Todd C. Miller, upstream maintainer).

All research credit belongs to Rich Mirch / Stratascale and the sudo
maintainers. SKELETONKEY is the bundling and bookkeeping layer only.

## SKELETONKEY role

🟢 **Structural escape (config-gated).** No offsets, no leak, no race.
`detect()` gates on the sudo version (the host-restricted rule lives in a
sudoers source the user usually cannot read — that opacity is the bug),
so a VULNERABLE verdict means "vulnerable sudo present; an abusable rule
may exist". `exploit()` best-effort reads `/etc/sudoers` +
`/etc/sudoers.d/*` for a user-spec whose host field is neither the
current hostname nor `ALL` (or takes the host from
`SKELETONKEY_SUDO_HOST`), witnesses with `sudo -n -h <host> id -u`, and
pops `sudo -h <host> /bin/bash` (override via `SKELETONKEY_SUDO_CMD`)
only on a confirmed uid-0 witness — never claims root it did not get.

Mitigation: upgrade sudo to 1.9.17p1+. Architecture-agnostic
(pure userspace). Joins the shared `sudo` family alongside
`sudo_chwoot`, `sudo_samedit`, `sudo_runas_neg1`, and `sudoedit_editor`.
