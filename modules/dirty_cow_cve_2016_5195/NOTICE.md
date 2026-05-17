# NOTICE — dirty_cow (CVE-2016-5195)

## Vulnerability

**CVE-2016-5195** — Copy-on-write race via `/proc/self/mem` + `madvise`
→ arbitrary file write into the page cache.

## Research credit

Discovered by **Phil Oester**, October 2016. The bug had been latent in
the kernel since ~2007.

Original advisory: <https://dirtycow.ninja/>
Upstream fix: mainline 4.9 (commit `19be0eaffa3a`, Oct 2016).

## SKELETONKEY role

Two-thread Phil-Oester-style race: writer thread via
`/proc/self/mem` vs. madvise(MADV_DONTNEED) thread. Targets the
`/etc/passwd` UID field flip + `su` for the root shell. Useful for
**old systems coverage** — RHEL 6/7 (3.10 baseline), Ubuntu 14.04
(3.13), Ubuntu 16.04 (4.4), embedded boxes, IoT.

Ships auditd watch on `/proc/self/mem` and a sigma rule for non-root
mem-open patterns.
