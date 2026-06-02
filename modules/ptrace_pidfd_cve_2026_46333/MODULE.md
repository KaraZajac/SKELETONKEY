# ptrace_pidfd — CVE-2026-46333

`__ptrace_may_access()` dumpable-race credential-descriptor theft via
`pidfd_getfd(2)`.

## The bug

When a privileged process drops its credentials, the kernel resets its
`dumpable` flag so that lower-privileged processes can no longer attach
to it. CVE-2026-46333 is a logic flaw in `__ptrace_may_access()`: there
is a narrow window during the credential drop in which the process is
*still reachable* through ptrace-family access checks even though its
`dumpable` state should already have closed that path.

`pidfd_getfd(2)` performs a `PTRACE_MODE_ATTACH_REALCREDS` access check
before duplicating a descriptor out of the target process. During the
stale window that check wrongly succeeds, so an unprivileged process can
pull descriptors — a root-opened credential file, or an authenticated
D-Bus / socket channel — out of a transiently-privileged process and
re-use them under its own uid.

## Affected range

| | |
|---|---|
| Flaw introduced | v4.10-rc1 (Nov 2016) in `__ptrace_may_access` |
| Exploit vector added | `pidfd_getfd(2)` in v5.6 (Jan 2020) |
| Fixed upstream | mainline, 2026-05-14 |
| Debian backports | 5.10.251 · 6.1.172 · 6.12.88 · 7.0.7 |

Branches Debian does not ship (5.15 / 6.6 / 6.18 / 6.19) are reported on
the version-only verdict; run `--exploit ptrace_pidfd --i-know` to fire
the real primitive and confirm empirically.

## Trigger / detection

`detect()` consults the shared host fingerprint, returns `OK` below 5.6
(no vector) or for patched branches, otherwise `VULNERABLE`. No active
probe — the empirical confirmation lives in the exploit path, which
spawns a setuid victim and sweeps `pidfd_getfd()` over its descriptor
table, reporting any uid-0-owned descriptor captured from a non-root
context.

## Fix / mitigation

Upgrade the kernel. As a runtime stopgap, `kernel.yama.ptrace_scope=2`
(or `3`) closes the `pidfd_getfd` path because it gates the same
`__ptrace_may_access(ATTACH)` check; `--mitigate` applies it and
`--cleanup` reverts it.

## Credit

Qualys Threat Research Unit (2026-05-20). See `NOTICE.md`.
