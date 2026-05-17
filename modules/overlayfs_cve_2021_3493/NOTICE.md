# NOTICE — overlayfs (CVE-2021-3493)

## Vulnerability

**CVE-2021-3493** — Ubuntu overlayfs userns file-capability injection
→ host root via setcap'd binaries in a userns-mounted overlay.

## Research credit

Reported by **Vasily Kulikov**, April 2021. Ubuntu-specific because
upstream didn't enable unprivileged userns-overlayfs-mount until 5.11.

Advisory: USN-4915-1 / USN-4916-1 (Canonical, April 2021).

Public PoC: vsh-style userns + overlayfs + xattr injection chain.

## IAMROOT role

Detect parses `/etc/os-release` for `ID=ubuntu`, checks
`unprivileged_userns_clone` sysctl, and with `--active` performs the
mount as a fork-isolated probe. The full exploit performs the
userns+overlayfs mount, plants a setcap'd carrier binary in the
upper layer, and execs it from the unprivileged side to obtain root
on the host. Ships auditd rules covering `mount(overlay)` and
`setxattr(security.capability)`.
