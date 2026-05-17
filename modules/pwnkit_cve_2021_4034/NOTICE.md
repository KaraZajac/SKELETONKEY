# NOTICE — pwnkit

## Vulnerability

**CVE-2021-4034** — pkexec argv[0]=NULL → environment-variable
injection → arbitrary code execution as root.

## Research credit

Discovered and disclosed by the **Qualys Research Team**, January 2022.

Original advisory:
<https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt>

Upstream fix: polkit 0.121 (Jan 2022).

## IAMROOT role

The exploit module follows the canonical Qualys-style chain: writes
payload.c + gconv-modules cache, compiles via the target's gcc,
execve's pkexec with NULL argv and crafted envp. Handles both the
legacy ("0.105") and modern ("126") polkit version string formats.
Falls back gracefully on hosts without a compiler.

This is IAMROOT's first **userspace** LPE — not a kernel bug.
