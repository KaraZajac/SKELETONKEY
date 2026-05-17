# NOTICE — cgroup_release_agent (CVE-2022-0492)

## Vulnerability

**CVE-2022-0492** — cgroup v1 `release_agent` privilege check in the
wrong namespace → host root from a rootless container or unprivileged
userns by mounting cgroup v1 and writing to `release_agent`.

## Research credit

Discovered by **Yiqi Sun** + **Kevin Wang** (Trend Micro Research),
January 2022.

Original writeup:
<https://blog.trendmicro.com/cve-2022-0492-from-cgroup-loophole-to-container-breakout/>

Upstream fix: mainline 5.17 (commit `24f6008564183`, March 2022).

## SKELETONKEY role

**Universal structural exploit — no per-kernel offsets, no race.**
unshare(USER | MOUNT | CGROUP), mount cgroup v1 RDP controller,
write `release_agent` → `./payload`, trigger via
`notify_on_release` + cgroup process exit.

Kept in the corpus as a portable "containers misconfigured"
demonstration — works across every kernel below the fix without any
tuning. Ships auditd rules covering cgroupfs mounts and
`release_agent` writes.
