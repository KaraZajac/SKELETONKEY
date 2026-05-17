# NOTICE — ptrace_traceme (CVE-2019-13272)

## Vulnerability

**CVE-2019-13272** — `PTRACE_TRACEME` on a parent that subsequently
execve's a setuid binary leaves the now-elevated process traceable by
the unprivileged child → cred escalation via ptrace shellcode inject.

## Research credit

Discovered by **Jann Horn** (Google Project Zero), June 2019.

Project Zero issue: <https://bugs.chromium.org/p/project-zero/issues/detail?id=1903>
Upstream fix: mainline 5.1.17 (commit `6994eefb0053`, June 2019).

Branch backports: 4.4.182 / 4.9.182 / 4.14.131 / 4.19.58 / 5.0.20 / 5.1.17.

## SKELETONKEY role

Full jannh-style chain: fork → child `PTRACE_TRACEME` → child
sleep+attach → parent `execve` setuid bin (pkexec/su/passwd
auto-selected) → child wins stale `ptrace_link` → POKETEXT x86_64
shellcode → root sh.

x86_64-only; ARM/other archs return PRECOND_FAIL cleanly. No exotic
preconditions — doesn't need userns. Works on default-config systems
including locked-down environments without unprivileged_userns_clone.
