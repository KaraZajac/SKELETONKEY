# refluxfs — CVE-2026-64600

"RefluXFS" — a time-of-check/time-of-use race in the XFS **reflink
copy-on-write** path that lets **any unprivileged local user overwrite the
on-disk contents of any file they can read**, on any XFS volume mounted with
`reflink=1` that they can write to. No user namespace, no capability, no crafted
filesystem image, no kernel offsets. It has been present since reflink direct-I/O
CoW landed in **4.11 (2017)** — a nine-year window.

This is the corpus's first XFS module, and its first **data-oriented** kernel
bug: the primitive is an arbitrary *file content* overwrite, not memory
corruption.

> **🟢 Full chain (`--full-chain`), VM-verified end-to-end.**
> `skeletonkey --exploit refluxfs --i-know --full-chain` lands root: it
> reflink-clones `/etc/passwd`, races the CoW window, strips root's password
> field on disk (`root:x:` → `root::`), evicts the stale page cache, and
> returns `EXPLOIT_OK`; `su root` (empty password) then gives uid 0. **Without**
> `--full-chain` the module runs a safe reachability trigger only, confined to
> files the caller owns. See "Full-chain verification" below.

## The bug

`xfs_direct_write_iomap_begin()` (`fs/xfs/xfs_iomap.c`) reads the data-fork
extent map under `ILOCK`. To allocate a transaction it must wait for log space,
so `xfs_reflink_fill_cow_hole()` (`fs/xfs/xfs_reflink.c`) **drops `ILOCK`**. On
re-acquiring it, the code re-queries the refcount btree at the **original**
physical block number (`imap->br_startblock`) — and **never re-reads the data
fork**.

A second `O_DIRECT` writer, holding only the coarser `IOLOCK`, can complete an
entire CoW cycle inside that window: allocate block Y, write it, and remap via
`xfs_reflink_end_cow()`. The first writer's `imap` now points at a block owned
solely by the reflink **source**. Its stale refcount lookup returns `1`, it
concludes the block is private, and writes to it in place — landing attacker
data on the source file's on-disk blocks.

Three consequences follow, and they drive the whole module design:

1. **No offsets, no ROP, no KASLR/SMEP/SMAP.** There is nothing to port per
   kernel build. Qualys is explicit that SELinux enforcing, container
   boundaries and seccomp are equally irrelevant.
2. **The victim's inode is never written.** The data is applied to the shared
   physical block *underneath* it, so `mtime`/`ctime`/size do not change and
   there is no kernel log output. **File-integrity monitoring does not fire.**
3. **It persists across reboots**, because the change is on disk.

The public demonstration (RHEL 10.2) reflink-clones `/etc/passwd` into
`/var/tmp`, races concurrent direct-I/O writes against the clone, thereby
rewriting `/etc/passwd` itself to strip root's password, and runs `su`.

## Affected range

| | |
|---|---|
| Introduced | **4.11** (2017-02, commit `3c68d44a2b49`, "xfs: allocate direct I/O COW blocks in iomap_begin") |
| Fixed upstream | commit `2f4acd0fcd86` ("xfs: resample the data fork mapping after cycling ILOCK") — merged **2026-07-16**, released **7.2-rc4** |
| Stable backports | **7.1.4** (`e705d81a7193`) · **6.18.39** (`206c09b04dc5`) · **6.12.96** (`44f891bc0889`) |
| Affected, no upstream fix | 6.6 / 6.1 / 5.15 / 5.14 / 5.10 / 4.19 / 4.18 LTS lines (per the CNA record at time of writing) |
| Not affected | < 4.11 — includes RHEL/CentOS **7** (3.10 predates reflink) |
| NVD class | CWE-362 (race) → CWE-367 (TOCTOU). NVD had published **no CWE and no CVSS vector** at time of writing |
| CISA KEV | no (disclosed 2026-07-22) |

**The exposure is distro-shaped, not kernel-shaped.** What matters is whether
XFS+reflink is the installer default:

| Exploitable out of the box | Not reachable by default |
|---|---|
| RHEL 8/9/10 · CentOS Stream 8/9/10 · Rocky/AlmaLinux 8/9/10 · Oracle Linux 8/9/10 (RHCK + UEK R6/R7/8) · CloudLinux 8/9/10 · Fedora Server ≥ 31 · Amazon Linux 2023 (and AL2 AMIs from 2022-12) | Debian · Ubuntu · Fedora Workstation · SLES · openSUSE · Arch (ext4/btrfs defaults — unless an XFS volume was added deliberately) |

### ⚠️ The version gate has a real blind spot here

The affected population is overwhelmingly **RHEL-family**, and those vendors
backport fixes **without bumping the upstream base version** — a patched RHEL 8
kernel still reports `4.18.0-xxx.el8`. An upstream-version gate cannot see that.

So on rpm-family hosts, a `VULNERABLE` verdict is a statement about the
**upstream base version only**. `detect()` prints that warning explicitly rather
than implying it checked the erratum. Confirm against the vendor advisory
(RHSA / ELSA / ALSA / RLSA) before acting on it.

## Trigger / detection

Unlike a pure kernel race, this bug's reachability **can** be established safely
and deterministically, so `detect()` is a version gate **plus a real
precondition probe**:

- **Passive** — is there a writable directory on a mounted XFS filesystem?
  Identified via `statfs(2)` `f_type == XFS_SUPER_MAGIC`, **not** by a
  successful `FICLONE`, because btrfs implements `FICLONE` too and is
  unaffected. No such directory → `PRECOND_FAIL`, the correct verdict on a
  stock Debian/Ubuntu host.
- **Active** (`--active` / `--auto`) — confirms `reflink=1` empirically by
  cloning and removing two 4 KiB files, rather than assuming the `mkfs.xfs`
  default. `reflink=0` → no shared extents can exist → `PRECOND_FAIL`.
- **Override** — `SKELETONKEY_XFS_ASSUME_REFLINK=1` (force reachable) / `0`
  (force unreachable), for when you know the fleet's storage layout better than
  a local probe can. This also drives the unit tests.

### `--full-chain` — the real `/etc/passwd` root pop

With `--full-chain`, `exploit()` performs the actual privilege escalation:

1. **Pre-flight, before touching anything.** Confirms the target
   (`/etc/passwd`, or `$SKELETONKEY_REFLUXFS_TARGET`) is root-owned and fits in
   one block, and **crafts the payload first** — the original file with root's
   password field emptied (`root:x:` → `root::`), **every other line preserved
   byte-for-byte**, padded with newlines to the exact original size. If it
   cannot produce a payload that keeps both root and the invoking user's line,
   it refuses and touches nothing. (A naive port that truncates the tail drops
   `sshd`/`nobody`/the caller and bricks login — this is the single most
   important safety property of the implementation.)
2. **Backup.** Copies the target aside so failure or `cleanup()` can restore it.
3. **Race.** 32 writers push the crafted block at a reflink-clone of the target
   while 8 helpers churn `ftruncate`/`fdatasync`, up to a 90 s budget. A won
   race lands the crafted block on the target's still-shared physical block.
4. **Cache eviction.** The overwrite bypasses the target inode, so its clean
   page-cache pages are never invalidated — a `su` immediately after would read
   the *stale* old passwd. The module issues `POSIX_FADV_DONTNEED` (needs only
   an `O_RDONLY` fd) so subsequent buffered readers see the new bytes.
5. **Verify (via `O_DIRECT`, not the cache) and report.** Confirms the on-disk
   root line is now `root::`; if the write was torn, it restores from backup and
   fails. On success returns `EXPLOIT_OK` and prints `su root` (empty password).

`cleanup()` (run as root after the pop) restores `/etc/passwd` from the backup.
The overwrite is persistent and survives reboot, so restoring matters.

#### The private-extent precondition (not in the public writeup)

The race only fires when the target's extent refcount is **exactly** the
attacker-clone pair — i.e. the target's extent must be **private** going in. The
mechanism: the block starts at refcount 2 (target + attacker clone), the
concurrent CoW drops it to 1, and the stale writer then reads "1 → private". If
the target is *already* reflink-shared with a third file, the post-CoW refcount
stays > 1, the writer correctly does CoW, and nothing corrupts.

This was found during verification: the stock Rocky 9 cloud image ships
`/etc/passwd` **pre-shared** (its block had refcount > 1 in the base image), and
the attack failed against it across ~41 000 rounds. Rewriting the file so its
extent became private — with byte-identical content, exactly what any
`useradd`/`passwd`/`vipw` does — made it fall in ~2 000 rounds. So the
exploitable state is the *normal* administered state; the cloud image was
accidentally protected by how it was built. `detect() --active` reports the
target's extent state (`filefrag -v /etc/passwd | grep shared` checks it by
hand), and the full chain warns when the target is pre-shared.

### `--full-chain` verification (2026-07-23, Rocky 9.8)

On `5.14.0-687.10.1.el9_8.0.1.x86_64`, unprivileged `uid=1000`, SELinux
**Enforcing**, against a private-extent `/etc/passwd`:

| | |
|---|---|
| `--exploit refluxfs --i-know --full-chain` | **`EXPLOIT_OK`**, 3/3 wins (1244 / 3716 / 7913 rounds, 4–30 s) |
| `su root` (empty password) afterwards | **`uid=0(root)`** |
| Accounts preserved | all 25 lines; `root`/`sk`/`sshd`/`nobody` intact |
| `/etc/passwd` metadata after overwrite | size/inode/**mtime/ctime unchanged**, only content — FIM-invisible |
| `cleanup` (as root) | restored `/etc/passwd` from backup, removed backup |
| Plain `--exploit` (no `--full-chain`) | safe trigger, `EXPLOIT_FAIL`, target untouched |
| Pre-shared `/etc/passwd` | not attackable (~41 000 rounds, no win) — as predicted |

### The safe default trigger

Without `--full-chain`, `exploit()` forks an isolated child that creates a
private `mkdtemp` scratch directory on the XFS mount and works **only on two
files it owns**:

- **(A) deterministic + safe** — writes a donor file, `FICLONE`-clones it, and
  confirms via **`FIEMAP_EXTENT_SHARED`** that the clone's extent really is
  shared (refcount > 1), plus that `O_DIRECT` opens succeed. That is a
  read-only observation that the exact filesystem state the bug misjudges
  exists here. Reflink cloning is an ordinary supported operation, so this
  phase is safe on any kernel.
- **(B) hard-bounded window exercise** — races **8** concurrent `O_DIRECT`
  4 KiB writes against the clone while **2** helper threads cycle
  `ftruncate`/`fdatasync` to keep the transaction allocator dropping `ILOCK` to
  wait for log space, for at most **16 rounds / 2 s**. Then it stops and reads
  the donor back **with `O_DIRECT`** — a buffered read would be served from the
  page cache that the corruption bypasses, and would hide a win.

This default path is **deliberately under-driven** (the public PoC and the
`--full-chain` path use 32 writers and 8 helpers) and **never clones or targets
a file it does not own** — the destructive `/etc/passwd` overwrite lives only
behind `--full-chain` (above). The default `exploit()` always returns
`EXPLOIT_FAIL`.

If the race *is* won on the safe path, the module says so loudly: that is
CVE-2026-64600 confirmed present, empirically, with the damage contained to
4 KiB of the operator's own scratch file.

## VM verification (2026-07-23)

Confirmed on **Rocky Linux 9.8 / `5.14.0-687.10.1.el9_8.0.1.x86_64`** under
qemu/KVM with 6 vCPUs — the stock GenericCloud installer layout, root on
`/dev/vda4` XFS with `reflink=1`, no provisioner changes:

| Check | Result |
|---|---|
| `detect()` on real XFS | **VULNERABLE** (found writable XFS at `/var/tmp`) |
| rpm-family backport caveat | fired correctly |
| `--active` FICLONE witness | **reflink CONFIRMED** |
| Phase A shared extent | **`FIEMAP_EXTENT_SHARED` set** (btrfs never reported it; XFS does) |
| Phase A `O_DIRECT` gate | available |
| Shipped trigger (8 writers / 2 helpers / 2 s) | ran 16 rounds, **did not win** — *by design* |
| Scratch cleanup | no artifacts left |
| Build on el9 gcc | clean |

**The underlying bug was separately confirmed winnable on that kernel.** The
`--full-chain` run above is the definitive proof — the same reflink-CoW race
rewrote `/etc/passwd` and landed root **3/3** (1244 / 3716 / 7913 rounds). An
earlier *non-destructive* measurement, driven at the public PoC's parameters
(32 writers / 8 helpers, 60 s) but confined to two files the test user owned,
won **4/4** (first divergence after **69, 114, 170 and 494 rounds**): a racing
`O_DIRECT` write landing on a still-shared block and rewriting the donor's
on-disk bytes — the arbitrary-overwrite primitive, observed directly, contained
entirely to attacker-owned files.

Note carefully what this does and does not say. The shipped trigger **not**
winning in 2 s on a kernel that is provably vulnerable is exactly the designed
behaviour, and is the concrete reason a non-win must **never** be read as
"patched" — trust the version gate and the vendor erratum instead.

### Why this ranks *above* the other reconstructed race triggers

`bad_epoll` (12) and `ghostlock` (11) sit at the bottom of the `--auto` safety
ranking because a won race frees a live `struct file` or corrupts the kernel
**stack** — silent destabilisation or near-certain panic. Neither applies here.
RefluXFS corrupts **file data, not kernel memory**: there is no oops, no KASAN
report, no panic risk, and the blast radius of a win is one 4 KiB scratch file
we created and delete. That is why `refluxfs` carries safety rank **55** — it is
genuinely safe to run, and the ranking should say so. The VM run above bears
this out: the bug was won 4/4 times on a vulnerable kernel with no oops, no
dmesg output and no instability.

## Detection — the obvious rule does not work

**Do not rely on `-w /etc/passwd -p wa`, AIDE, or Tripwire for this CVE.** The
attacker never issues a `write(2)` against the victim inode; XFS applies their
data to the shared physical block beneath it. Size, `mtime` and `ctime` are
unchanged and nothing is logged. Anyone relying on FIM to catch a `passwd`
modification is blind to this bug *by construction*.

What does work, in descending order of fidelity:

1. **The reflink itself** — `ioctl(fd, FICLONE, srcfd)` where `FICLONE` is
   `0x40049409`. auditd can match the request number **exactly**, so it does not
   flood, and the attack cannot avoid it. Tune out `cp --reflink=auto`, podman
   and `systemd-nspawn` image work.
2. **`O_DIRECT` opens** — `openat` flags `& 0x4000`. Also on the critical path,
   and rare outside databases and backup agents.
3. **Content-vs-metadata drift** — because the bytes change while `mtime` does
   not, hashing `/etc/passwd`, `/etc/shadow` and the setuid binaries on a
   schedule and alerting when the *content* hash moves **without** a
   corresponding `mtime` change is a near-zero-false-positive detector for this
   whole bug class.

The shipped rules cover all three: auditd/sigma anchor on the `FICLONE` request
number and `O_DIRECT` opens (correlated per-pid, plus the post-exploitation
euid-0 transition), falco adds the high-fidelity "reflinked a file owned by
another user" condition, and — unusually for a kernel bug — the **yara** rule is
genuinely the right tool, matching the on-disk artifact (`/etc/passwd` with a
password-less root entry or an added uid-0 account) precisely because there is
no metadata trace for FIM to find.

## Fix / mitigation

Upgrade the kernel (≥ 7.1.4 / 6.18.39 / 6.12.96 on-branch, or 7.2+; on
RHEL-family, the vendor erratum) **and reboot**.

There is **no partial mitigation**, which is why `mitigate()` is `NULL`:
`reflink` is a superblock feature that cannot be disabled on a live filesystem,
`O_DIRECT` cannot be turned off, and — because this is a data-oriented bug —
SELinux enforcing, container boundaries, KASLR, SMEP, SMAP and seccomp are all
irrelevant. Qualys puts it plainly: *"This isn't a vulnerability you can harden
around, isolate, or live-patch."*

`cleanup()` restores `/etc/passwd` from the `--full-chain` backup (run it as
root after the pop: `su root`, then `skeletonkey --cleanup refluxfs`), then
sweeps any `skeletonkey-refluxfs-*` scratch directories left behind if a run was
killed mid-round; normal runs remove their own.

## Credit

Discovery and research: **Qualys Threat Research Unit (TRU)**; the blog post is
authored by **Saeed Abbasi**, and the technical advisory credits model-assisted
kernel analysis performed with **Anthropic**. Upstream fix `2f4acd0fcd86`. See
`NOTICE.md`.
