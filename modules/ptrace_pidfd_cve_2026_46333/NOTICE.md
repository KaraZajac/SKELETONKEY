# NOTICE — ptrace_pidfd (CVE-2026-46333)

## Vulnerability

**CVE-2026-46333** — a logic flaw in the Linux kernel's
`__ptrace_may_access()` path leaves a privileged process that is
*dropping* its credentials briefly reachable through ptrace-family
operations, even though its `dumpable` flag should already have closed
that path. Paired with `pidfd_getfd(2)`, an unprivileged local user can
capture open file descriptors and authenticated IPC channels from a
dying privileged process and re-use them under their own uid → local
root and credential disclosure.

The underlying flaw has resided in mainline since **v4.10-rc1**
(November 2016); the `pidfd_getfd(2)` exploitation vector was added in
**v5.6** (January 2020). Affects default installations of Debian 13,
Ubuntu 24.04 / 26.04, Fedora 43 / 44, SUSE, AlmaLinux, and CloudLinux.

## Research credit

Discovered and disclosed by **Qualys Threat Research Unit (TRU)**,
published 2026-05-20. The four proof-of-concept exploits demonstrated
by Qualys targeted `chage`, `ssh-keysign`, `pkexec`, and
`accounts-daemon`.

- Qualys advisory:
  <https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path>
- Upstream fix: mainline, committed 2026-05-14.
- Debian-tracked stable backports: 5.10.251 (bullseye) / 6.1.172
  (bookworm) / 6.12.88 (trixie) / 7.0.7 (forky, sid).

All research credit for finding and analysing this bug belongs to
Qualys. SKELETONKEY is the bundling and bookkeeping layer only.

## SKELETONKEY role

🟡 **Primitive / ported-from-disclosure — not yet VM-verified.**
`detect()` is version-pinned against the Debian backport thresholds
above (kernels < 5.6 are reported OK, lacking the bundled vector).
`exploit()` fires the real primitive: it spawns a setuid victim,
`pidfd_open()`s it, and sweeps `pidfd_getfd()` across its descriptor
table during the credential-drop window, recording whether a root-owned
descriptor is actually captured from a non-root context. It returns
`EXPLOIT_FAIL` unless it can witness euid 0 — the target-specific
fd-weaponization that lands a root shell is **not** bundled until it can
be verified end-to-end against a real vulnerable VM, in keeping with the
project's no-fabrication rule.

`--mitigate` sets `kernel.yama.ptrace_scope=2` (the check `pidfd_getfd`
rides); `--cleanup` restores it. Architecture-agnostic — the technique
steals descriptors rather than injecting shellcode.
