# NOTICE — overlayfs_setuid (CVE-2023-0386)

## Vulnerability

**CVE-2023-0386** — overlayfs `copy_up` preserves the setuid bit
across mount-namespace boundaries → host root via a setuid carrier
placed in the lower layer.

## Research credit

Discovered and disclosed by **Xkaneiki**, January 2023.

Public PoC + writeup:
<https://github.com/xkaneiki/CVE-2023-0386>

Upstream fix: mainline 6.2-rc6 (commit `4f11ada10d0a`, Jan 2023).
Branch backports: 5.10.169 / 5.15.92 / 6.1.11.

## IAMROOT role

Distro-agnostic — no per-kernel offsets, no race. Places a setuid
binary in an overlay lower, mounts via fuse-overlayfs userns trick,
executes from the upper layer to inherit the setuid bit + root euid.

Auditd rules cover overlayfs mounts and unexpected setuid copy-ups.
