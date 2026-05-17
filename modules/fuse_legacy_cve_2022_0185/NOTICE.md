# NOTICE — fuse_legacy (CVE-2022-0185)

## Vulnerability

**CVE-2022-0185** — `legacy_parse_param` in fsconfig() doesn't validate
`PAGE_SIZE` against the running `fs_context`'s key/value length →
4 KB heap OOB write → cross-cache UAF → cred overwrite from a
rootless container.

## Research credit

Discovered and disclosed by **William Liu** + **Jamie Hill-Daniel**
(Crusaders of Rust), January 2022.

Original writeup: <https://www.willsroot.io/2022/01/cve-2022-0185.html>
Public PoC: <https://github.com/Crusaders-of-Rust/CVE-2022-0185>

Upstream fix: mainline 5.16.2 (Jan 2022).
Branch backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171.

## SKELETONKEY role

userns+mountns reach, `fsopen("cgroup2")` + double
`fsconfig(FSCONFIG_SET_STRING, "source", ...)` fires the 4k OOB,
msg_msg cross-cache groom in kmalloc-4k. MSG_COPY read-back detects
whether the OOB landed in an adjacent neighbour — the sanity gate
that prevents fake-success claims.

`--full-chain` extends with forged m_list/m_ts overflow toward
modprobe_path via the shared finisher.

**Container-escape angle** — relevant to rootless docker/podman/snap.
