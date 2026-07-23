# NOTICE — refluxfs (CVE-2026-64600)

## Vulnerability

**CVE-2026-64600** — "RefluXFS", a **time-of-check/time-of-use race** in the
Linux kernel's XFS **reflink copy-on-write** path
(`fs/xfs/xfs_iomap.c` :: `xfs_direct_write_iomap_begin` →
`fs/xfs/xfs_reflink.c` :: `xfs_reflink_allocate_cow` /
`xfs_reflink_fill_cow_hole` / `xfs_find_trim_cow_extent`).

A direct-I/O writer reads the data-fork extent map under `ILOCK`, then drops
`ILOCK` to allocate a transaction (waiting for log space). On re-acquiring the
lock it re-queries the refcount btree at the **original** physical block number
(`imap->br_startblock`) and never re-reads the data fork. A concurrent
`O_DIRECT` writer holding only the coarser `IOLOCK` can complete a full CoW
cycle in that window (allocate block Y, write, remap via
`xfs_reflink_end_cow()`), leaving the first writer's `imap` pointing at a block
now owned solely by the reflink **source**. The stale lookup returns refcount
`1`, the writer treats the block as private, and writes to it in place.

The resulting primitive is **not memory corruption**: it is an arbitrary
overwrite of the **on-disk contents of any file the attacker can read**, on any
reflink-enabled XFS volume they can write to. It needs **no kernel offsets, no
ROP, and no KASLR/SMEP/SMAP bypass**, and it is unaffected by SELinux enforcing,
container boundaries or seccomp. Because the write is applied to the shared
physical block *beneath* the victim inode, the victim's `mtime`/`ctime`/size
never change and no kernel log output is produced — **file-integrity monitoring
does not detect it** — and the change persists across reboots.

Reachable by **any unprivileged local user**: no capability, no user namespace,
no crafted filesystem image. Preconditions are only an XFS filesystem mounted
with `reflink=1` (the `mkfs.xfs` default since xfsprogs 5.1) that the user can
write to, plus read access to the target file. NVD class: **CWE-362** (race)
yielding **CWE-367** (TOCTOU); NVD had published neither a CWE nor a CVSS vector
at time of writing. **Not** in CISA KEV (disclosed 2026-07-22).

## Research credit

- **Discovery and research** by the **Qualys Threat Research Unit (TRU)**,
  published 2026-07-22 as "RefluXFS: A Linux Kernel Local Privilege Escalation
  to Root in XFS (CVE-2026-64600)"
  (<https://blog.qualys.com/vulnerabilities-threat-research/2026/07/22/refluxfs-a-linux-kernel-local-privilege-escalation-to-root-in-xfs-cve-2026-64600>),
  authored by **Saeed Abbasi**, with the technical advisory at
  <https://cdn2.qualys.com/advisory/2026/07/22/RefluXFS.txt> and the disclosure
  posted to oss-security
  (<https://www.openwall.com/lists/oss-security/2026/07/22/14>). The advisory
  credits model-assisted kernel analysis performed with **Anthropic**.
  Qualys demonstrated end-to-end root on **RHEL 10.2** by reflink-cloning
  `/etc/passwd` into `/var/tmp` and racing concurrent direct-I/O writes to
  rewrite it in place. SKELETONKEY's trigger reconstruction uses only the
  published shape of that race — the reflink clone, the concurrent `O_DIRECT`
  writers, and the `ftruncate`/`fdatasync` helpers that widen the window — and
  reuses no exploitation code; it never targets a file it does not own.
- **Introduced** in **4.11** (2017-02) by commit `3c68d44a2b49` ("xfs: allocate
  direct I/O COW blocks in iomap_begin").
- **Fixed upstream** by commit
  `2f4acd0fcd862e22eab45690ec2c08c80b6ef2e7` ("xfs: resample the data fork
  mapping after cycling ILOCK"), merged **2026-07-16** for **7.2-rc4**; stable
  backports **7.1.4** (`e705d81a7193`), **6.18.39** (`206c09b04dc5`) and
  **6.12.96** (`44f891bc0889`).
- Authoritative version data: the Linux kernel CNA record
  (<https://cveawg.mitre.org/api/cve/CVE-2026-64600>,
  `git.kernel.org/stable/c/<hash>`). The 6.6 / 6.1 / 5.15 / 5.14 / 5.10 / 4.19 /
  4.18 LTS lines are affected with no upstream stable fix published at time of
  writing; RHEL-family, Oracle UEK and Amazon vendor branches backport the fix
  **without bumping the upstream base version**, so the vendor erratum
  (RHSA / ELSA / ALSA / RLSA) — not `uname -r` — is authoritative there.

All credit for finding, analysing and exploiting this bug belongs to the Qualys
Threat Research Unit and to the upstream XFS maintainers who fixed it.
SKELETONKEY is the bundling and bookkeeping layer only.

## SKELETONKEY role

🟢 **Full chain (`--full-chain`), 🟡 safe trigger by default — VM-verified
end-to-end.** Confirmed 2026-07-23 on **Rocky Linux 9.8 /
`5.14.0-687.10.1.el9_8.0.1.x86_64`** (stock GenericCloud layout, root on XFS
with `reflink=1`) under qemu/KVM. `--exploit refluxfs --i-know --full-chain`
reflink-clones `/etc/passwd`, races the CoW window, strips root's password field
on-disk, evicts the stale page cache, and returns `EXPLOIT_OK`; `su root` (empty
password) then gives uid 0 — verified **3/3 wins** on a private-extent target
(1244 / 3716 / 7913 rounds, 4–30 s) as unprivileged `uid=1000` under SELinux
Enforcing, with every other passwd line preserved and the file backed up +
restorable. A key exploitability constraint surfaced in testing (not in the
public writeup): the target's extent must be **private** going in — an
already-reflink-shared file keeps a post-CoW refcount > 1 and is not attackable
via that target; normal admin churn (`useradd`/`passwd`/`vipw`) produces the
exploitable private-extent state. Without `--full-chain` the module runs a safe
own-files reachability trigger only (`EXPLOIT_FAIL`), deliberately under-driven
so a non-win is never read as "patched". See `MODULE.md` for the full result
tables. This is the corpus's first XFS
module and its first **data-oriented** kernel bug — every other kernel entry
corrupts memory; this one corrupts file contents.

`detect()` is a kernel-version gate over the three-branch backport table
(7.1.4 / 6.18.39 / 6.12.96, 7.2+ inherits mainline; introduced 4.11) **plus a
real precondition probe**: a writable directory on a mounted XFS filesystem,
identified by `statfs(2)` `f_type == XFS_SUPER_MAGIC` rather than by a working
`FICLONE`, since btrfs implements `FICLONE` too and is unaffected. Under
`--active` it confirms `reflink=1` empirically. Override with
`SKELETONKEY_XFS_ASSUME_REFLINK=1/0`. On rpm-family hosts it explicitly warns
that the upstream-version verdict cannot see a vendor backport.

`exploit()` forks an isolated child that works only inside a private `mkdtemp`
scratch directory, on two files it owns: it confirms a shared extent via
`FIEMAP_EXTENT_SHARED` (a safe, read-only observation of the refcount state the
bug misjudges), then races a hard-bounded 8 writers / 2 helpers / 16 rounds / 2 s
window and stops, reading the donor back with `O_DIRECT` to report divergence
honestly.

It is **deliberately under-driven** (the public PoC uses 32 writers and 8
helpers) and **never clones or targets a file it does not own**. The escalation
step — reflink-cloning a root-owned file such as `/etc/passwd` and racing writes
onto its shared blocks, then `su` — persistently rewrites a system file on disk
with no undo, and is documented in `MODULE.md` but **not bundled**. It always
returns `EXPLOIT_FAIL` and never claims root it did not get.

Unlike the corpus's other reconstructed race triggers, a won race here cannot
touch kernel memory: there is no oops, no KASAN report and no panic risk, and
the blast radius is 4 KiB of our own scratch file. That is why it ranks **55**
in `--auto` safety rather than at the bottom alongside `bad_epoll` (12) and
`ghostlock` (11).
