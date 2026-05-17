# Pwnkit — CVE-2021-4034

> 🔵 **DETECT-ONLY** as of 2026-05-16. Full exploit follows.

## Summary

Polkit's `pkexec` parses argv assuming argc ≥ 1. With `argc == 0`, the
parsing reads past `argv[0]` into the contiguous envp region, treating
the first env string as if it were argv[0]. By placing `GCONV_PATH=`
crafted entries in the environment and naming a controlled file such
that libc's iconv() loads it as a gconv module, an unprivileged user
gets code execution as root via the setuid pkexec binary.

Disclosed by Qualys 2022-01-25. Bug existed since pkexec's first
release in 2009 — affects every distribution shipping a vulnerable
polkit until 0.121 (or distro backport).

## Affected versions

- **All polkit ≤ 0.120** (i.e., pkexec from 2009 onward) before the
  fix landed.
- Patched in upstream **polkit 0.121** (2022-01-25).
- Distro backports vary:
  - Ubuntu: 0.105-26ubuntu1.3 (focal), 0.105-31ubuntu0.1 (impish), etc.
  - Debian: 0.105-31+deb11u1 (bullseye), 0.105-26+deb10u1 (buster)
  - RHEL: polkit-0.115-13.el7_9 (RHEL 7), polkit-0.117-9.el8_5.1 (RHEL 8)

## SKELETONKEY detect logic (current)

1. Resolve pkexec binary (`/usr/bin/pkexec` or `which pkexec`)
2. If not present → SKELETONKEY_OK (no attack surface)
3. Run `pkexec --version` and parse version
4. Compare to known-fixed thresholds; report VULNERABLE if below

## Exploit logic (follow-up)

Canonical Qualys / public Pwnkit PoC:

1. Build a malicious shared object that `exit(setuid(0)); system("/bin/sh")`
2. Build a `GCONV_PATH=./X` env entry plus `CHARSET=X` so libc's
   iconv (used by pkexec for argv decoding) loads our .so
3. `execve("/usr/bin/pkexec", { NULL }, envp)` — argc=0 triggers the
   read past argv[0], which sees our GCONV_PATH crafted string, then
   pkexec gives us root context, the gconv module loads our .so as
   root, we drop to a shell

~200 lines including the embedded .so generator. Phase 7 follow-up
commit lands the full version.

## Detection rules (shipped)

`detect/auditd.rules` — flags pkexec invocations from non-root.

## References

- https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
- https://nvd.nist.gov/vuln/detail/CVE-2021-4034
