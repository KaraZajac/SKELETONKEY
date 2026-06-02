# sudo_host — CVE-2025-32462

sudo `-h`/`--host` option honored beyond `-l` → abuse a host-restricted
sudoers rule for local root.

## The bug

`sudo -h <host>` (a.k.a. `--host`) exists so that, combined with `-l`,
you can list your sudo privileges *as they would apply on another host*.
The flaw: sudo also consulted the `-h` value when **running a command**
(and in `sudoedit`), so the host portion of a sudoers rule — normally
fixed to the machine you're on — becomes attacker-chosen.

If your sudoers contains a rule like:

```
alice  webhost01 = (root) /usr/bin/systemctl
```

then on a *different* machine `alice` normally can't use it. With the
bug, `sudo -h webhost01 /usr/bin/systemctl ...` runs as root on the
local box. With a broader rule (`webhost01 = (ALL) ALL`), `sudo -h
webhost01 /bin/bash` is a root shell.

This matters most where one sudoers file (or LDAP/SSSD sudoers) is shared
across a fleet and rules are scoped per host.

## Affected range

| | |
|---|---|
| Affected | sudo 1.8.8 → 1.9.17p0 (~12-year-old behaviour) |
| Fixed | sudo 1.9.17p1 |
| Weakness | CWE-863 (Incorrect Authorization) |
| Severity | CVSS 8.8 (High); not in CISA KEV |

## Trigger / detection

`detect()` reads the sudo version (shared host fingerprint, else a live
`sudo --version`) and returns VULNERABLE inside `[1.8.8, 1.9.17p0]`,
OK otherwise. The exploitable precondition — a host-restricted sudoers
rule — is not reliably probeable from an unprivileged context, so the
empirical confirmation lives in the exploit path.

`exploit()`:
1. Resolves the host token to abuse: `SKELETONKEY_SUDO_HOST` env var, or
   a best-effort scan of readable `/etc/sudoers` + `/etc/sudoers.d/*` for
   a user-spec whose host is neither the current hostname nor `ALL`.
2. Witnesses with `sudo -n -h <host> id -u` (non-interactive).
3. On a uid-0 witness, execs `sudo -h <host> /bin/bash`
   (override the command with `SKELETONKEY_SUDO_CMD`).

Returns `EXPLOIT_FAIL` with operator guidance when no abusable rule is
discoverable — it never fabricates root.

## Fix / mitigation

Upgrade sudo to 1.9.17p1 or later. There is no safe runtime toggle for
the `-h` behaviour short of the patch.

## Credit

Rich Mirch — Stratascale CRU (2025-06-30). See `NOTICE.md`.
