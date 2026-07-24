## SKELETONKEY v0.10.0 — the exploit-verification release

This release moves the corpus from **detect-verified** to **out-of-band
exploit-verified**. Every headline claim below was witnessed in a VM by an
independent root proof (a root-owned artifact, an `/etc/shadow` read, or a
setuid-bash sentinel) — never by the module's own self-report. Full ledger:
`docs/EXPLOITED.md`; per-run records: `docs/VERIFICATIONS.jsonl`.

### Headline: 11 modules confirmed landing `uid=0` out of band

| module | CVE | verified on |
|---|---|---|
| `refluxfs` | CVE-2026-64600 | Rocky 9.8 / 5.14.0-687 — `/etc/passwd` full chain |
| `overlayfs` | CVE-2021-3493 | Ubuntu 20.04.0 / 5.4.0-26 — **direct uid=0 witness** |
| `overlayfs_setuid` | CVE-2023-0386 | Ubuntu 22.04.0 / 5.15.0-25 — **rewritten (libfuse)** |
| `pwnkit` | CVE-2021-4034 | Ubuntu 20.04.0 / polkit 0.105 — **fixed** |
| `sudo_runas_neg1` | CVE-2019-14287 | Ubuntu 18.04.2 / sudo 1.8.21p2 |
| `sudoedit_editor` | CVE-2023-22809 | Ubuntu 22.04.0 / sudo 1.9.9 — **fixed** |
| `sudo_host` | CVE-2025-32462 | Ubuntu 22.04.0 / sudo 1.9.9 |
| `ptrace_traceme` | CVE-2019-13272 | Ubuntu 18.04.0 / 4.15.0-50 — **rewritten** |
| `sudo_samedit` | CVE-2021-3156 | Ubuntu 18.04.0 / sudo 1.8.21p2 — **rewritten (Baron Samedit)** |
| `dirty_pipe` | CVE-2022-0847 | mainline 5.16.0 — **rewritten, 3 bugs fixed** |
| `dirty_cow` | CVE-2016-5195 | mainline 4.8.0 — **rewritten, false-OK fixed** |

### Integrity: four modules were falsely claiming root — all fixed

A corpus-wide **false-`EXPLOIT_OK` audit** found four modules that reported
success while obtaining **no root at all**, via the dispatcher's "an `execve`
transferred, so treat it as success" path (the exec'd helper then failed):
`pwnkit`, `ptrace_traceme`, `dirty_pipe`, `dirty_cow`. All four now verify root
by an out-of-band artifact before claiming success. `dirty_pipe`/`dirty_cow`
additionally reverted `/etc/passwd` via `drop_caches` (needs root) — as an
unprivileged caller that **corrupted the running system's `/etc/passwd`**; both
now revert through the Dirty Pipe/COW primitive itself, leaving the file
byte-identical. The audit was then broadened to **every** `EXPLOIT_OK` site: all
are now backed by a real check (root-owned artifact `stat`, `getxattr`
bug-signature, `/etc/passwd` grep, `setuid(0)==0` gate, or page-cache
`verify_plant`). No false positives remain.

### New / rewritten working exploits

- **`ptrace_traceme`** (CVE-2019-13272) — the shipped sequence had the mechanism
  backwards; rewritten to the Jann Horn/bcoles technique (child becomes
  non-degraded root via its own setuid-execve under a privileged tracer), lands
  real root.
- **`sudo_samedit`** (CVE-2021-3156, "Baron Samedit") — the corpus's hardest
  userspace target; ported blasty's NSS `libnss_X` hijack, lands root as a
  non-sudoer on the first grooming attempt.
- **`overlayfs_setuid`** (CVE-2023-0386) — rewritten with libfuse (setuid-root
  FUSE lower + overlay copy-up).
- **`dirty_pipe`** / **`dirty_cow`** — rewritten to the reliable "known-hash into
  root's password field + `su` over a pty" escalation, with primitive-based
  revert; `dirty_cow` verified on a pre-4.8.3 kernel.

### Other fixes

- **Systemic userns bug** fixed in `cgroup_release_agent` + `af_packet2`:
  `getuid()`/`getgid()` were read *after* `unshare(CLONE_NEWUSER)` (→ 65534), so
  the `uid_map` write was rejected and userns-root silently failed.
- **Offset resolver** (`core/offsets.c`): env-provided kernel offsets
  (`SKELETONKEY_MODPROBE_PATH`, …) were silently wiped under `kptr_restrict` (i.e.
  on every default host), blocking every `--full-chain` primitive. Fixed.
- **Robust `su` helper**: the su-over-pty step now polls for the prompt with a
  hard 20s cap so a misbehaving `su` can never hang the module (and thus never
  block a revert). Latent `readback[16]` overflow fixed. `netfilter_xtcompat`
  now includes `<linux/if.h>` for `IFNAMSIZ` (builds on older kernel headers).
- **`overlayfs`** upgraded from a `getxattr` proxy to a **direct uid=0 witness**.

### Kernel primitives — scope note

The ~13 kernel-primitive modules (`nf_tables` & friends) remain honest
`EXPLOIT_FAIL` trigger/groom scaffolds. `nf_tables`' kernel was confirmed
vulnerable and the offset plumbing fixed, but landing root needs a
Notselwyn-scale port; and even the most tractable primitive
(`netfilter_xtcompat`, CVE-2021-22555) needs its exact target kernel+config —
Andy Nguyen's reference exploit does not land on mainline 5.4/5.8. These are
per-target, per-primitive exploit-dev, documented in `docs/EXPLOITED.md`.

---

## SKELETONKEY v0.9.14 — new LPE module: refluxfs (CVE-2026-64600)

Adds **`refluxfs` — CVE-2026-64600 "RefluXFS"** (Qualys Threat Research Unit),
taking the corpus to **46 modules / 41 CVEs** and opening a brand-new subsystem:
**XFS reflink copy-on-write** (`fs/xfs/xfs_iomap.c`, `fs/xfs/xfs_reflink.c`). It
is also the corpus's first **data-oriented** kernel bug — every other kernel
entry in the set corrupts memory; this one corrupts file contents.

`xfs_direct_write_iomap_begin()` reads the data-fork extent map under `ILOCK`,
then `xfs_reflink_fill_cow_hole()` **drops `ILOCK`** to allocate a transaction
(i.e. to wait for log space). On re-acquiring it, the code re-queries the
refcount btree at the **original** physical block number (`imap->br_startblock`)
and **never re-reads the data fork**. A second `O_DIRECT` writer holding only the
coarser `IOLOCK` can complete an entire CoW cycle inside that window — allocate
block Y, write it, remap via `xfs_reflink_end_cow()` — leaving the first writer's
mapping pointing at a block now owned solely by the reflink **source**. The stale
lookup returns refcount `1`, the writer concludes the block is private, and
writes to it in place, landing attacker data on the source file's on-disk blocks.

Three properties make this unlike anything else in the corpus:

- **No offsets, no ROP, no KASLR/SMEP/SMAP.** The primitive is an arbitrary
  overwrite of the *on-disk contents of any readable file*, so there is nothing
  to port per kernel build and no `--full-chain` offset entry to fill. Qualys is
  explicit that SELinux enforcing, container boundaries and seccomp are equally
  irrelevant: *"This isn't a vulnerability you can harden around, isolate, or
  live-patch."*
- **File-integrity monitoring cannot see it.** The data is applied to the shared
  physical block *beneath* the victim inode. No `write(2)` ever targets it, so
  `mtime`/`ctime`/size are unchanged and nothing is logged — `-w /etc/passwd -p
  wa`, AIDE and Tripwire all stay silent. The change persists across reboots.
- **The exposure is distro-shaped, not kernel-shaped.** What matters is whether
  XFS+reflink is the installer default: **RHEL/CentOS Stream/Rocky/AlmaLinux/
  Oracle/CloudLinux 8-10, Fedora Server ≥ 31 and Amazon Linux 2023** are
  exploitable out of the box; Debian, Ubuntu, Fedora Workstation, SLES, openSUSE
  and Arch default to ext4/btrfs and are not reachable. RHEL/CentOS 7 (3.10) was
  never affected.

Introduced **4.11** (2017-02, `3c68d44a2b49`) — a nine-year window. Fixed by
`2f4acd0fcd86` ("xfs: resample the data fork mapping after cycling ILOCK"),
merged **2026-07-16** for **7.2-rc4**; stable backports **7.1.4** / **6.18.39** /
**6.12.96**. The 6.6 / 6.1 / 5.15 / 5.14 / 5.10 / 4.19 / 4.18 lines have no
upstream stable fix in the CNA record at time of writing. CWE-362 → CWE-367; NVD
published neither a CWE nor a CVSS vector at time of writing; not in CISA KEV.

🟢 **Full chain (`--full-chain`), 🟡 safe trigger by default — VM-verified
end-to-end.** `--exploit refluxfs --i-know --full-chain` reflink-clones
`/etc/passwd`, races the CoW window, strips root's password field on-disk
(`root:x:` → `root::`, the public PoC's technique), evicts the stale page cache,
and returns `EXPLOIT_OK`; `su root` with an empty password then yields uid 0.
Confirmed on Rocky Linux 9.8 / `5.14.0-687.10.1.el9_8.0.1` — **3/3 wins** on a
private-extent target (1244 / 3716 / 7913 rounds, 4–30 s) as unprivileged
`uid=1000` under **SELinux Enforcing**, with every other passwd line preserved,
the file backed up first and restored on failure (`--cleanup` restores after the
pop). A naive port that truncates the tail would drop `sshd`/the caller and brick
login; preserving every line is the implementation's key safety property.

**Exploitability constraint discovered during verification (not in the Qualys
writeup):** the race only fires when the target's extent is **private** going in.
An already-reflink-shared file keeps a post-CoW refcount > 1 and is not
attackable via that target — some fresh cloud images ship `/etc/passwd`
pre-shared (Rocky 9's did, and the attack failed against it across ~41 000
rounds), while normal admin churn (`useradd`/`passwd`/`vipw`) rewrites it into
the exploitable private-extent state. `detect() --active` now reports which state
the target is in. Without `--full-chain` the module runs a safe own-files
reachability trigger only (`EXPLOIT_FAIL`), deliberately under-driven.
Unlike the corpus's other race
modules, `detect()` is **not** a pure version gate: this bug's reachability is
safely observable, so it pairs the three-branch version table with a **real
storage precondition** — a writable directory on a mounted XFS filesystem,
identified by `statfs(2)` `f_type == XFS_SUPER_MAGIC` and deliberately **not** by
a successful `FICLONE`, since btrfs implements `FICLONE` too and is unaffected.
No such directory → `PRECOND_FAIL`, the correct verdict on a stock Debian/Ubuntu
host. Under `--active` it confirms `reflink=1` empirically; override with
`SKELETONKEY_XFS_ASSUME_REFLINK=1/0`. On rpm-family hosts it warns explicitly
that RHEL/Oracle/Rocky/Alma backport **without bumping the upstream version** (a
patched el8 kernel still reports `4.18.0-*`), so the verdict reflects the
upstream base version only — check the RHSA/ELSA/ALSA/RLSA erratum.

`exploit()` forks an isolated child that creates a private `mkdtemp` scratch
directory and works **only on two files it owns**: **(A)** it writes a donor,
`FICLONE`-clones it, and confirms the shared extent via **`FIEMAP_EXTENT_SHARED`**
plus an `O_DIRECT` gate — a read-only, deterministic observation that the exact
refcount state the bug misjudges exists here; then **(B)** it races **8**
concurrent `O_DIRECT` 4 KiB writes against the clone with **2**
`ftruncate`/`fdatasync` helpers cycling the `ILOCK`, for at most **16 rounds /
2 s**, and stops — reading the donor back with `O_DIRECT`, because a buffered read
would be served from the page cache the corruption bypasses and would hide a win.
It is deliberately under-driven against the public PoC's 32 writers and 8
helpers, and it **never clones or targets a file it does not own**: the step that
yields root — reflink-cloning `/etc/passwd` and racing writes onto *its* shared
blocks, then `su` — persistently rewrites a system file on disk with no undo, and
is documented but **not bundled**. Always returns `EXPLOIT_FAIL`.

Note the safety inversion versus the other reconstructed triggers: a won race
here corrupts **file data, not kernel memory**, so there is no oops, no KASAN
report and no panic path, and the blast radius is 4 KiB of a scratch file the
module then deletes. `refluxfs` therefore carries safety rank **55** — far above
`bad_epoll` (12) and `ghostlock` (11) — and `--cleanup` sweeps any
`skeletonkey-refluxfs-*` directories left by an interrupted run.

Detection gets a genuinely unusual treatment, because the obvious rule is the one
that fails. auditd/sigma anchor on the two operations the attack cannot avoid —
`ioctl` request **`0x40049409`** (`FICLONE`, matched exactly so it does not flood)
and `openat` with `O_DIRECT` (`& 0x4000`) — plus the post-exploitation euid-0
transition; falco adds the high-fidelity "reflinked a file owned by another user"
condition. And for once the **yara** rule is the right tool for a kernel bug:
since FIM is structurally blind here, it matches the *on-disk artifact* — a
`passwd` file with a password-less root entry or an added uid-0 account. The
module docs also recommend content-hash-vs-`mtime` drift monitoring, which is a
near-zero-false-positive detector for this entire bug class.

14 new `detect()` unit rows cover the backport boundaries, the 4.11 introduction
gate, the el8/el9 upstream bases, the "newer than some entries but not all" case,
and the no-XFS `PRECOND_FAIL` path (**148 tests total, 0 failures**).

**VM-verified 2026-07-23 — the corpus's first rpm-family verification**, taking
the empirical count to **29 of 41 CVEs**. Target: **Rocky Linux 9.8 /
`5.14.0-687.10.1.el9_8.0.1.x86_64`** under qemu/KVM with 6 vCPUs. The stock
GenericCloud layout needed **no provisioner changes at all** — root is
`/dev/vda4` XFS with `reflink=1` out of the box, which is precisely why this CVE
hits the RHEL family so broadly. `detect()` returned `VULNERABLE`, the
rpm-family vendor-backport caveat fired, the `--active` FICLONE witness confirmed
reflink, phase A observed `FIEMAP_EXTENT_SHARED` on a real shared extent, the
scratch dir self-cleaned, and the source built clean on el9 gcc.

The **underlying bug was separately confirmed winnable** on that kernel: the
`--full-chain` root pop above is the proof (the same race rewrote `/etc/passwd`,
3/3). An earlier *non-destructive* measurement at the public PoC's parameters
(32 writers / 8 helpers, 60 s), confined to two files the test user owned, won
**4 out of 4 runs**, first divergence after **69, 114, 170 and 494 rounds** — a
racing `O_DIRECT` write landing on a still-shared block and rewriting the donor's
on-disk bytes, the arbitrary-overwrite primitive observed directly with no oops
and no dmesg output (as expected for a data-oriented bug).

Worth stating plainly, because it is the whole point of the design: the shipped
trigger **did not win** in its 2 s budget on a kernel that is provably
vulnerable. That is intended under-driving, not a defect — and it is the concrete
reason a non-win must **never** be recorded as "patched". Trust the version gate
and the vendor erratum.

Credit: **Qualys Threat Research Unit** (blog by **Saeed Abbasi**; the technical
advisory credits model-assisted kernel analysis performed with **Anthropic**),
and the upstream XFS maintainers who fixed it.

---

## SKELETONKEY v0.9.13 — new LPE module: ghostlock (CVE-2026-43499)

Adds **`ghostlock` — CVE-2026-43499 "GhostLock"** (VEGA / Nebula Security,
"IonStack part II"), taking the corpus to **45 modules / 40 CVEs** and opening a
brand-new subsystem: **rtmutex / futex requeue-PI** (`kernel/locking/rtmutex.c`).
It is also the corpus's first kernel-**stack** use-after-free — every other UAF
in the set is heap/slab. On the `-EDEADLK` deadlock-rollback path,
`remove_waiter()` operates on `current` instead of the actual waiter task while
unwinding a proxy lock in `rt_mutex_start_proxy_lock()` (reached from
`futex_requeue()`); if a concurrent PI-chain priority walk — driven from another
CPU via `sched_setattr()` — runs at that instant, `pi_blocked_on` is cleared on
the wrong task and an on-stack `rt_mutex_waiter` is left dangling, becoming a
controlled kernel write when the rbtree is later rotated over the reused frame.
Reachable by **any unprivileged user** (CVSS 7.8, PR:L) — plain `futex(2)` +
`sched_setattr(2)`, no user namespace, no capability, only `CONFIG_FUTEX_PI`
(universal). It has existed since PI-futex requeue landed in **2.6.39** — ~15
years across every distribution. The public exploit weaponises it (Android/Pixel)
via a "KernelSnitch" futex-bucket page leak → forged waiter → `struct file`
`f_op` → configfs/ashmem R/W → pipe physical R/W → cred patch; ~97% stable on
kernelCTF, $92,337. Introduced 2.6.39; fixed `3bfdc63936dd` (merged 7.1-rc1),
stable backports 7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175 — the
5.15/5.10/5.4/4.19 LTS branches are affected with no upstream fix. CWE-416 (race
root cause CWE-362); not in CISA KEV.

🟡 **Trigger (reconstructed) — reachability-only, deliberately under-driven, not
VM-verified.** `detect()` is a pure kernel-version gate over a five-branch
backport table (7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175, 7.1+ inherits
mainline; 5.15/5.10/5.4/4.19 affected with no fix; < 2.6.39 not affected) — no
userns/CONFIG probe (`CONFIG_FUTEX_PI` assumed). `exploit()` forks an isolated
child that **(A)** deterministically confirms the `-EDEADLK` `remove_waiter()`
rollback path is reachable — a **safe** witness, since without a concurrent
priority walk the unwind creates no dangling pointer (validated on real hardware:
the requeue-PI cycle returns `-EDEADLK` reliably) — then **(B)** exercises the
actual race a hard-bounded 24 iterations / 2 s with a sibling-CPU
`sched_setattr(SCHED_BATCH)` storm, and stops. It does **not** widen the
`copy_from_user` window (no memfd/`PUNCH_HOLE`), does **not** spray or reoccupy
the freed stack frame, and does **not** bundle the KernelSnitch leak →
forged-waiter → fops/configfs/ashmem/pipe R/W → cred-patch chain (Android/Pixel-
specific, per-build offsets). Returns `EXPLOIT_FAIL`. It carries the corpus's
**lowest `--auto` safety rank (11)** — a won race corrupts the kernel stack and
drives a near-arbitrary pointer write (near-certain panic), so `--auto` only
reaches for it after every safer vulnerable module. Unlike most kernel races
GhostLock has a **real detection signature**: a futex requeue-PI op returning
`-EDEADLK` (glibc never provokes this) plus tight-loop
`sched_setattr(SCHED_BATCH)` on a sibling thread — the shipped auditd/sigma rules
anchor on `sched_setattr` + the post-exploitation euid-0 transition, the
falco/eBPF rule on the requeue-PI-EDEADLK tell; no yara. Wired: registry,
Makefile, safety rank (11), 9 `detect()` test rows (incl. the multi-branch
"newer than all" case 6.13.0 → VULNERABLE), CVE metadata (CWE-416 / T1068 /
not-KEV), README + CVES.md + website counts (45/40), RELEASE_NOTES v0.9.13, and a
verify-vm target (sweep pending). Also corrects pre-existing website drift left
by v0.9.12 (index.html body counts + the missing `bad_epoll` corpus pill).
Credits VEGA / Nebula Security + the upstream fix `3bfdc63936dd`.

## SKELETONKEY v0.9.12 — new LPE module: bad_epoll (CVE-2026-46242)

Adds **`bad_epoll` — CVE-2026-46242 "Bad Epoll"** (Jaeyoung Chung /
`J-jaeyoung`, submitted to Google's kernelCTF), taking the corpus to **44
modules / 39 CVEs** and opening a brand-new subsystem: **epoll /
`fs/eventpoll.c`**. A race-condition use-after-free on the file-teardown
path — `ep_remove()` clears `file->f_ep` under `file->f_lock` but keeps
using the file inside the critical section (`hlist_del_rcu()` +
`spin_unlock()`), so a concurrent `__fput()` observes the transient NULL,
skips `eventpoll_release_file()`, and frees a `struct eventpoll` still in
use. The public exploit weaponises the 8-byte UAF write via a cross-cache
attack to a `struct file`, arbitrary kernel read through
`/proc/self/fdinfo`, and a ROP chain — ~99% reliable through a
~6-instruction window, and reachable by **any unprivileged user with no
user namespace, no CONFIG, and no capability** (which also means there is
no unprivileged-userns stopgap — the only fix is to patch). Introduced by
`58c9b016e128` (Linux 6.4); fixed by `a6dc643c6931` (merged 7.1-rc1),
stable backport 7.0.13. CWE-416 (race root cause CWE-362); not in CISA
KEV. Also affects Android.

🟡 **Trigger (reconstructed) — deliberately under-driven, primitive-only,
not VM-verified.** A *won* race frees a live `struct eventpoll` — real
memory corruption that rarely trips KASAN, so a completed race can
silently destabilise a vulnerable host. `detect()` is therefore a pure
kernel-version gate (vulnerable iff ≥ 6.4 and below the fix on-branch;
stable backport 7.0.13, 7.1+ inherits; 6.1/5.10 not affected) with **no
active probe** — there is no safe way to distinguish vulnerable from
patched without winning the race. `exploit()` forks a CPU-pinned child
that builds the epoll race pair and exercises the `ep_remove`-vs-`__fput`
concurrent-close window a **hard-bounded** 48 attempts / 2 s (widened with
`close(dup())` false-sharing storms), snapshots the eventpoll slab, and
returns `EXPLOIT_FAIL`; it does not grind the race to a win, does not do
the cross-cache reclaim, and does not bundle the `fdinfo` arbitrary-read +
ROP root-pop (per-build offsets refused). It carries the corpus's
**lowest `--auto` safety rank (12)** — a kernel race that frees a live
`struct file` is the least predictable class, so `--auto` only reaches for
it after every safer vulnerable module. Detection is intentionally
weak/structural (epoll syscalls are ubiquitous and the exploit rarely
trips KASAN) — the shipped auditd/sigma/falco rules key on the
post-exploitation euid-0 transition, with no yara; treat this as much as a
blue-team "your stack is nearly blind to this" teaching case as an
offensive one. Wired: registry, Makefile, safety rank (12), 5 `detect()`
test rows (version gating), CVE metadata (CWE-416 / T1068 / not-KEV),
README + CVES.md + website counts (44/39), RELEASE_NOTES v0.9.12, and a
verify-vm target (sweep pending). Credits Jaeyoung Chung + the upstream
fix in `NOTICE.md`. Reconstructed from the public kernelCTF PoC and not
VM-verified, so the verified count stays 28 of 39.

## SKELETONKEY v0.9.11 — new LPE module: nft_catchall (CVE-2026-23111)

Adds **`nft_catchall` — CVE-2026-23111**, taking the corpus to **43
modules / 38 CVEs**. The newest nftables LPE: a **use-after-free** in the
nf_tables transaction-abort path. `nft_map_catchall_activate()` carries an
inverted condition (a stray `!`) so the abort path processes *active*
catch-all map elements instead of skipping them — a catch-all GOTO element
drives a chain's use-count to zero, and a following `DELCHAIN` frees the
chain while the catch-all verdict still references it → UAF. From an
unprivileged user (user namespaces + nftables) it escalates to root via a
`modprobe_path` / `selinux_state` ROP. Fixed upstream by commit `f41c5d1`;
CWE-416, CVSS 7.8; not in CISA KEV. Public reproduction + analysis by
**FuzzingLabs**.

🟡 **Trigger (reconstructed) — primitive-only, not VM-verified.** This is
one more UAF in the corpus's most-covered subsystem (`nf_tables`,
`nft_set_uaf`, `nft_payload`, `nft_pipapo`, …) and ships on the same
contract as `nf_tables` (CVE-2024-1086): a fork-isolated trigger that
fires the bug class and stops. `detect()` version-gates against the
Debian backports (upstream thresholds 6.1.164 / 6.12.73 / 6.18.10;
catch-all set elements arrived ~5.13) **and** requires unprivileged
user-namespace clone — a vulnerable kernel with userns locked down is
`PRECOND_FAIL`. `exploit()` builds a verdict map with a catch-all GOTO
element and provokes an aborting batch transaction to drive the abort-path
UAF, observes slabinfo, and returns `EXPLOIT_FAIL`. The per-kernel leak +
arbitrary-R/W + `modprobe_path` ROP is **not** bundled (per-build offsets
refused), and the trigger is reconstructed from the public analysis rather
than VM-verified — it never claims root it did not get. Ships auditd +
sigma + falco rules, ATT&CK T1068 + CWE-416 metadata, six new `detect()`
unit-test rows (version + userns gating), credits FuzzingLabs + the
upstream fix in `NOTICE.md`, and a verify-vm target (sweep pending). Not
VM-verified, so the verified count stays 28 of 38.

## SKELETONKEY v0.9.10 — new LPE module: cifswitch (CVE-2026-46243)

Adds **`cifswitch` — CVE-2026-46243 "CIFSwitch"** (Asim Manizada,
2026-05-28), taking the corpus to **42 modules / 37 CVEs**. The newest
kernel-7-era LPE not already covered: a ~19-year-old logic flaw in
`fs/smb/client/cifs_spnego.c` where the `cifs.spnego` request-key type
accepts key descriptions created by *userspace* (`add_key(2)` /
`request_key(2)`) without verifying the request came from the in-kernel
CIFS client. The description carries authority-bearing fields
(`pid`/`uid`/`creduid`/`upcall_target`) that the root `cifs.upcall`
helper trusts as kernel-originating; combined with user+mount namespace
tricks, an unprivileged user coerces `cifs.upcall` into loading an
attacker NSS module as root. Fixed upstream by `3da1fdf4efbc` (merged
7.1-rc5); NVD class CWE-20; not in CISA KEV.

🟡 **Honest port — full chain not VM-verified.** `detect()` gates on the
kernel version (Debian backports 5.10.257 / 6.1.174 / 6.12.90 / 7.0.10)
**and** on the presence of the vulnerable userspace path — a vulnerable
kernel without `cifs-utils` reports `PRECOND_FAIL`, not a false
`VULNERABLE` (override the probe with `SKELETONKEY_CIFS_ASSUME_PRESENT=1`
/`0`). `exploit()` fires only the non-destructive primitive — `add_key(2)`
of a forged-but-benign `cifs.spnego` key, which does **not** invoke
`cifs.upcall` and loads nothing, revoked immediately — and treats a clean
accept as the empirical witness that userspace can forge the
authority-bearing key type. It then stops: the namespace-switch +
malicious-NSS-load root-pop is target/config-specific and is not bundled
until VM-verified, so it returns honest `EXPLOIT_FAIL` without a euid-0
witness (never fabricates root). `--mitigate` blocklists the `cifs`
module (`/etc/modprobe.d/skeletonkey-disable-cifs.conf`); `--cleanup`
reverts. Structural, arch-agnostic (keyring + namespace logic, no
shellcode). Ships auditd + sigma + falco rules, MITRE ATT&CK T1068 +
CWE-20 metadata, six new `detect()` unit-test rows, and credits Asim
Manizada in `NOTICE.md`. **Partially VM-verified** (2026-06-08, Ubuntu
24.04.4 / kernel 6.8.0-117, QEMU/HVF): `detect()`'s precondition + version
gating and the `add_key` primitive are confirmed — an independent
`python3` `ctypes` `add_key("cifs.spnego", …)` was accepted and the
module's `exploit()` reported "primitive CONFIRMED" then honest
`EXPLOIT_FAIL`. The full namespace+NSS root-pop and a patched-kernel
discriminator check remain pending, so cifswitch is **not** counted as a
verified end-to-end CVE — the verified count stays 28 of 37. Details in
the module `NOTICE.md` and `tools/verify-vm/targets.yaml`.

## SKELETONKEY v0.9.9 — install.sh needs no root; CVE-2022-0492 KEV drift

Two maintenance fixes, no new modules.

**`install.sh` never escalates to sudo.** SKELETONKEY is a privilege-
escalation tool — the operator by definition does *not* have root yet, so
the installer must not demand it. The old default wrote to `/usr/local/bin`
and fell back to `sudo mv` when that wasn't writable, prompting for a
password on exactly the unprivileged accounts this tool targets. It now
installs sudo-free: `/usr/local/bin` is used only when already writable,
otherwise it falls back to a per-user `$HOME/.local/bin` (honoring
`XDG_BIN_HOME`), created as needed. An explicit `SKELETONKEY_PREFIX` is
honored exactly and errors rather than escalating if unwritable. When the
chosen dir isn't on `$PATH` the installer prints the absolute path, and the
documented `curl … | sh && skeletonkey --auto --i-know` one-liner now
prepends `$HOME/.local/bin` to `$PATH` so it resolves on a fresh login. The
quickstart no longer prefixes `sudo` to `--scan`/`--audit`/`--auto` —
detection and escalation run as the unprivileged user; only writing audit
rules into `/etc/audit` legitimately needs root.

**Federal metadata drift (the failing scheduled build).** The weekly
`drift-check` caught two upstream changes since v0.9.8:

- **CVE-2022-0492 entered CISA KEV (2026-06-02).** The cgroup v1
  `release_agent` container-escape (`cgroup_release_agent`) is now on the
  Known Exploited Vulnerabilities catalog. The corpus reports **13 of 36**
  modules covering KEV-listed CVEs (was 12).
- **CVE-2026-46333 gained a CWE.** When `ptrace_pidfd` was added two weeks
  after disclosure, NVD had not yet classified it; it is now **CWE-269**
  (Improper Privilege Management).

A third, latent cause kept the gate red even after those two: when
`sudo_host` (CVE-2025-32462) was added in v0.9.8 its record was appended to
the *end* of `CVE_METADATA.json`, but the drift check compares the record
list in `discover_cves()`'s sorted order — so the out-of-order entry read
as drift regardless of its values. Regenerating via the script restores
sorted order.

Refreshed `CVE_METADATA.json`, the generated `cve_metadata.c` table, and
`KEV_CROSSREF.md` accordingly (README + website counts updated).

## SKELETONKEY v0.9.8 — two new LPE modules (ptrace_pidfd, sudo_host)

Adds the two most compelling recent Linux LPEs not already in the corpus,
taking it to **41 modules / 36 CVEs** (every year 2016 → 2026 still
covered).

**`ptrace_pidfd` — CVE-2026-46333** (Qualys TRU, 2026-05-20). A logic
flaw in the kernel's `__ptrace_may_access()` path leaves a process that
is *dropping* its credentials briefly reachable past its `dumpable`
boundary; `pidfd_getfd(2)` rides that window to steal a root-opened file
descriptor or authenticated channel from a transiently-privileged setuid
binary (chage / pkexec / ssh-keysign) or root daemon. Default-distro, no
userns, architecture-agnostic (descriptor theft, no shellcode). detect()
is version-pinned (predates-gate at pidfd_getfd's 5.6 introduction;
Debian backports 5.10.251 / 6.1.172 / 6.12.88 / 7.0.7). `--mitigate`
sets `kernel.yama.ptrace_scope=2`.

**`sudo_host` — CVE-2025-32462** (Rich Mirch / Stratascale, 2025-06-30;
sibling of v0.8.0's `sudo_chwoot`). sudo's `-h`/`--host` option, meant
only to pair with `-l`, was honored when running a command — so a
sudoers rule scoped to a host other than the current machine (and not
ALL) is usable via `sudo -h <host> <cmd>` for local root. Affects sudo
1.8.8 → 1.9.17p0 (fixed 1.9.17p1); CWE-863, CVSS 8.8. Most relevant to
fleet-wide / LDAP / SSSD sudoers.

Both are honest ports: detect() is version-pinned and unit-tested (10 new
detect() rows, all green in CI), and exploit() fires the real primitive
and returns `EXPLOIT_FAIL` unless it can witness euid 0 — never
fabricating root. Neither is VM-verified yet (both flagged "sweep
pending" in `tools/verify-vm/targets.yaml`), so the verified count stays
28 of 36. Each ships auditd + sigma + falco rules, MITRE ATT&CK + CWE
metadata, and credits the original researcher in its `NOTICE.md`.

## SKELETONKEY v0.9.7 — kernel_range drift fix + CI Node 24 readiness

Two maintenance fixes, no new modules.

**`fragnesia` kernel_range drift.** Debian backported CVE-2026-46300 to
the 5.10 oldstable branch (bullseye 5.10.257), a branch the module's
`kernel_patched_from` table didn't model — on a patched bullseye host
`detect()` would have false-positived VULNERABLE. Added the `{5,10,257}`
entry; the weekly `refresh-kernel-ranges.py` drift gate is green again.
(The other flagged modules are INFO-only "more permissive" thresholds
the check tolerates by design.)

**CI Node 24 readiness.** GitHub forces the Node 24 Actions runtime on
2026-06-16 and removes Node 20. Bumped every workflow action off its
Node-20 line:

- `actions/checkout` v4 → v6
- `actions/upload-artifact` v4 → v7
- `actions/download-artifact` v4 → v8
- `softprops/action-gh-release` v2 → v3

Each was reviewed against its changelog: the artifact flow uploads
default-zipped, uniquely-named artifacts and downloads the full set, so
none of the major-version breaking changes (opt-in direct uploads,
download-by-ID path changes) apply. This release is itself the
end-to-end test of the new artifact actions.

## SKELETONKEY v0.9.6 — `--auto` no longer prompts for sudo password

Two sudo modules' `detect()` bodies invoked `sudo -ln` to read the
user's allowed-commands list. The intent was non-interactive — `-ln`
should parse as `-l -n` (list + non-interactive). But some sudoers /
PAM configurations have been observed prompting for a password
anyway when the flags are bundled, defeating the point.

That meant `skeletonkey --auto --i-know` could hang on a sudo
password prompt during the corpus scan, even though the whole point
of an LPE tool is to *get* root without already having it.

Fix in `sudo_runas_neg1` and `sudoedit_editor`:

- `-n -l` written as separate flags (instead of bundled `-ln`)
- `</dev/null` redirect so sudo cannot fall back to reading the tty
  even if the PAM stack tries

Belt-and-suspenders. `--auto` is now guaranteed never to block on
tty input.

---

## SKELETONKEY v0.9.5 — kernel_range drift cleanup (the other half)

v0.9.4 fixed the `cve_metadata` drift but exposed a *second* drift
check (`kernel_range drift`) that had been hidden behind it. That
check compares each module's `kernel_patched_from` table against
Debian's security tracker. It had **11 TOO_TIGHT + 8 MISSING
findings across 12 modules** — meaning `detect()` would have
reported VULNERABLE on many kernels that Debian has on record as
patched (false-positives), or missed branches entirely.

Applied `tools/refresh-kernel-ranges.py --patch` recommendations
across:

- `cgroup_release_agent` — `{5,16,9}` → `{5,16,7}`
- `cls_route4` — `{5,10,143}` → `{5,10,136}`, `{5,18,18}` → `{5,18,16}`
- `dirty_cow` — `{4,7,10}` → `{4,7,8}`
- `dirty_pipe` — `{5,10,102}` → `{5,10,92}`
- `fragnesia` — `{6,12,91}` → `{6,12,90}`, `{7,0,10}` → `{7,0,9}`
  (the 7.0.10 entry I added in v0.9.4 was an NVD-vs-Debian off-by-one)
- `mutagen_astronomy` — added `{4,12,6}` backport entry
- `netfilter_xtcompat` — `{5,10,46}` → `{5,10,38}`
- `overlayfs_setuid` — `{6,1,27}` → `{6,1,11}`
- `pintheft` — added `{6,12,90}` Debian-trixie entry
- `ptrace_traceme` — `{4,19,58}` → `{4,19,37}`
- `sequoia` — `{5,10,52}` → `{5,10,46}`
- `tioscpgrp` — added `{5,9,15}` backport entry

All changes are correctness-improving (no kernel that was previously
flagged VULNERABLE-and-actually-vulnerable is now flagged OK; we just
stop false-positiving on kernels that Debian has on record as patched).

Build's `kernel_range drift` step now exits 0 with 0 TOO_TIGHT and 0
MISSING.

Also enabled `workflow_dispatch` on the build workflow so the
drift-check job can be manually triggered without waiting for the
weekly Monday-06:00-UTC cron.

---

## SKELETONKEY v0.9.4 — drift unblock, fragnesia range fix, infra docs

Quality-of-life follow-ups from the v0.9.3 review:

**Nightly CI drift-check unblocked.** v0.9.3's hand-applied
`core/cve_metadata.c` entries weren't reflected in
`docs/CVE_METADATA.json`, so the scheduled `build` workflow had
been red since 2026-05-25 even though push-triggered runs passed.
Regenerated both via the canonical script. Pintheft's CWE landed
as CWE-787 (NVD-derived) — previously NULL.

**fragnesia module range table corrected.** Same audit pattern that
found the dirtydecrypt bug in v0.9.3. NVD CVE-2026-46300 confirms
the SKBFL_SHARED_FRAG marker was introduced at 5.11 and the bug
spans every stable branch since. Previous range table had one entry
(`{7, 0, 9}`) — off-by-one against NVD's 7.0.10 fix point and
missing every other backport. Now models 6 backports + predates-5.11
introduction gate:

```c
{5, 15, 208}, /* 5.15-LTS */
{6,  1, 174}, /* 6.1-LTS  */
{6,  6, 141}, /* 6.6-LTS  */
{6, 12,  91}, /* 6.12-LTS */
{6, 18,  33}, /* 6.18-LTS */
{7,  0,  10}, /* 7.0      */
```

Test row added for the predates path (kernel 4.4 → OK).

**`tools/verify-vm/README.md` brought current.** The README was
written for the v0.6-era apt-pin-only workflow. Now documents the
v0.9.x infrastructure: mainline kernel pinning via
kernel.ubuntu.com, per-module provisioners
(`provisioners/<module>.sh`), two-phase prep→reboot→verify with
post-reboot kernel confirmation, GRUB_DEFAULT pinning in both apt
and mainline blocks.

**NVD lookups in `refresh-cve-metadata.py` get a curl fallback.**
v0.9.3 ran into Python's `urlopen` silently hanging on NVD's HTTP/2
endpoint (55-min process with the 30s timeout never firing — kernel
CLOSE_WAIT socket). The CISA path already had a curl fallback; the
NVD path now mirrors it. Future runs degrade gracefully when
urlopen wedges.

---

## SKELETONKEY v0.9.3 — CVE metadata refresh + dirtydecrypt range fix

**CVE metadata refresh (10 → 12 KEV).** Populated the 8 missing
entries in `core/cve_metadata.c` for v0.8.0 + v0.9.0 module additions.
Two of them are CISA-KEV-listed:

- **CVE-2018-14634** `mutagen_astronomy` — KEV-listed 2026-01-26 (CWE-190)
- **CVE-2025-32463** `sudo_chwoot` — KEV-listed 2025-09-29 (CWE-829)

Other 6 entries got CWE / ATT&CK technique metadata so `--explain` and
`--module-info` now surface WEAKNESS + THREAT INTEL correctly for them.
(`tools/refresh-cve-metadata.py` hangs on CISA's HTTP/2 endpoint via
Python urlopen — populated directly via curl + max-time as a workaround.)

**dirtydecrypt module bug fix.** Auditing dirtydecrypt's range table
against NVD's authoritative CPE match for CVE-2026-31635 surfaced that
`dd_detect()` was wrongly gating "predates the bug" on kernel < 7.0.
Per NVD, the rxgk RESPONSE bug entered at 6.16.1 stable; vulnerable
ranges are 6.16.1–6.18.22, 6.19.0–6.19.12, and 7.0-rc1..rc7. The fix:

- `dd_detect()` predates-gate now uses 6.16.1 (not 7.0)
- `patched_branches[]` table adds `{6, 18, 23}` for the 6.18 backport

Re-verified empirically: dirtydecrypt now correctly returns VULNERABLE
on mainline 6.19.7 (genuinely below the 6.19.13 backport). Previously
it returned OK there — a false negative that would have lied to anyone
running scan on a real vulnerable kernel.

---

## SKELETONKEY v0.9.2 — dirtydecrypt verified on mainline 6.19.7

One more empirical verification: **CVE-2026-31635 dirtydecrypt** confirmed
end-to-end on Ubuntu 22.04 + mainline 6.19.7. detect() correctly returns
OK ("kernel predates the rxgk RESPONSE-handling code added in 7.0"). Footer
goes 27 → 28.

Attempted but deferred: **CVE-2026-46300 fragnesia**. Mainline 7.0.5 kernel
.debs depend on `libssl3t64` / `libelf1t64` (the t64-transition libs
introduced in Ubuntu 24.04 / Debian 13). No Vagrant box with a Parallels
provider has those libs yet — `dpkg --force-depends` leaves the kernel
package in `iHR` (broken) state with no `/boot/vmlinuz` deposited. Marked
`manual: true` with rationale in `targets.yaml`. Resolvable when a
Parallels-supported ubuntu2404 / debian13 box becomes available.

---

## SKELETONKEY v0.9.1 — VM verification sweep (22 → 27)

Five more CVEs empirically confirmed end-to-end against real Linux VMs
via `tools/verify-vm/`:

| CVE | Module | Target environment |
|---|---|---|
| CVE-2019-14287 | `sudo_runas_neg1` | Ubuntu 18.04 (sudo 1.8.21p2 + `(ALL,!root)` grant via provisioner) |
| CVE-2020-29661 | `tioscpgrp`      | Ubuntu 20.04 pinned to `5.4.0-26` (genuinely below the 5.4.85 backport) |
| CVE-2024-26581 | `nft_pipapo`     | Ubuntu 22.04 + mainline `5.15.5` (below the 5.15.149 fix) |
| CVE-2025-32463 | `sudo_chwoot`    | Ubuntu 22.04 + sudo `1.9.16p1` built from upstream into `/usr/local/bin` |
| CVE-2025-6019  | `udisks_libblockdev` | Debian 12 + `udisks2` 2.9.4 + polkit allow rule for the verifier user |

Footer goes from `22 empirically verified` → `27 empirically verified`.

### Verifier infrastructure (the why)

These verifications required real plumbing work that didn't exist before:

- **Per-module provisioner hook** (`tools/verify-vm/provisioners/<module>.sh`)
  — per-target setup that doesn't belong in the Vagrantfile (build sudo
  from source, install udisks2 + polkit rule, drop a sudoers grant) now
  lives in checked-in scripts that re-run idempotently on every verify.
- **Two-phase provisioning** in `verify.sh` — prep provisioners run
  first (install kernel, set grub default, drop polkit rule), then a
  conditional reboot if `uname -r` doesn't match the target, then the
  verifier proper. Fixes the silent-fail where the new kernel was
  installed but the VM never actually rebooted into it.
- **GRUB_DEFAULT pin in both `pin-kernel` and `pin-mainline` blocks** —
  without this, grub's debian-version-compare picks the highest-sorting
  vmlinuz as default; for downgrades (stock 4.15 → mainline 4.14.70, or
  stock 5.4.0-169 → pinned 5.4.0-26) the wrong kernel won boot.
- **Old-mainline URL fallback** — kernel.ubuntu.com puts ≤ 4.15 mainline
  debs at `/v${KVER}/` not `/v${KVER}/amd64/`. Fallback handles both.

### Honest residuals — 7 of 34 still unverified

| Module | Why not verified |
|---|---|
| `vmwgfx` | needs a VMware guest; we're on Parallels |
| `dirty_cow` | needs ≤ 4.4 kernel — older than any supported Vagrant box |
| `mutagen_astronomy` | mainline 4.14.70 kernel-panics on Ubuntu 18.04 rootfs (`Failed to execute /init (error -8)` — kernel config mismatch). Genuinely needs CentOS 6 / Debian 7. |
| `pintheft` | needs RDS kernel module loaded (Arch only autoloads it) |
| `vsock_uaf` | needs `vsock_loopback` loaded — not autoloaded on common Vagrant boxes |
| `dirtydecrypt`, `fragnesia` | need Linux 7.0 — not yet shipping as any distro kernel |

All seven are flagged in `tools/verify-vm/targets.yaml` with `manual: true`
and a rationale.

---

## SKELETONKEY v0.9.0 — every year 2016 → 2026 now covered

Five gap-filling modules. Closes the 2018 hole entirely and thickens
2019 / 2020 / 2024.

### CVE-2018-14634 — `mutagen_astronomy` (Qualys)

Closes the 2018 gap. `create_elf_tables()` int-wrap → on x86_64, a
multi-GiB argv blob makes the kernel under-allocate the SUID
carrier's stack and corrupt adjacent allocations. CISA-KEV-listed
Jan 2026 despite the bug's age — legacy RHEL 7 / CentOS 7 / Debian
8 fleets still affected. 🟡 PRIMITIVE (trigger documented;
Qualys' full chain not bundled per verified-vs-claimed).
`arch_support: x86_64+unverified-arm64`.

### CVE-2019-14287 — `sudo_runas_neg1` (Joe Vennix)

`sudo -u#-1 <cmd>` → uid_t underflows to 0xFFFFFFFF → sudo treats it
as uid 0 → runs `<cmd>` as root even when sudoers explicitly says
"ALL except root". Pure userspace logic bug; the famous Apple
Information Security finding. detect() looks for a `(ALL,!root)`
grant in `sudo -ln` output. `arch_support: any`. Sudo < 1.8.28.

### CVE-2020-29661 — `tioscpgrp` (Jann Horn / Project Zero)

TTY `TIOCSPGRP` ioctl race on PTY pairs → `struct pid` UAF in
kmalloc-256. Affects everything through Linux 5.9.13. 🟡 PRIMITIVE
(race-driver + msg_msg groom). Public PoCs from grsecurity/spender
+ Maxime Peterlin. `arch_support: x86_64+unverified-arm64`.

### CVE-2024-50264 — `vsock_uaf` (a13xp0p0v / Pwnie 2025 winner)

AF_VSOCK `connect()` races a POSIX signal that tears down the
virtio_vsock_sock → UAF in kmalloc-96. **Pwn2Own 2024 + Pwnie Award
2025 winner.** Reachable as plain unprivileged user (no userns
required — unusual). Two public exploit paths: @v4bel + @qwerty
kernelCTF chain (BPF JIT spray + SLUBStick) and Alexander Popov's
msg_msg path (PT SWARM Sep 2025). 🟡 PRIMITIVE.
`arch_support: x86_64+unverified-arm64`.

### CVE-2024-26581 — `nft_pipapo` (Notselwyn II, "Flipping Pages")

`nft_set_pipapo` destroy-race UAF. Sibling to our `nf_tables` module
(CVE-2024-1086) — same Notselwyn "Flipping Pages" research paper,
different specific bug in the pipapo set substrate. Same family
detect signature. 🟡 PRIMITIVE.
`arch_support: x86_64+unverified-arm64`.

### Year-by-year coverage matrix

```
2016: ▓ 1     2021: ▓▓▓▓▓ 5     2025: ▓▓ 2
2017: ▓ 1     2022: ▓▓▓▓▓ 5     2026: ▓▓▓▓ 4
2018: ▓ 1 ←   2023: ▓▓▓▓▓▓▓▓ 8
2019: ▓▓ 2 ←  2024: ▓▓▓ 3 ←
2020: ▓▓ 2 ←
```

Every year 2016 → 2026 is now ≥1.

### Corpus growth

| | v0.8.0 | v0.9.0 |
|---|---|---|
| Modules registered | 34 | 39 |
| Distinct CVEs | 29 | 34 |
| Years with ≥1 CVE | 10 of 11 (missing 2018) | **11 of 11** |
| Detection rules embedded | 131 | 151 |
| Arch-independent (`any`) | 6 | 7 |
| VM-verified | 22 | 22 |

### Other changes

- All 5 new modules ship complete detection-rule corpus
  (auditd + sigma + yara + falco) — corpus stays at 4-format
  parity with the rest of the modules.
- `tools/refresh-cve-metadata.py` runs against 34 CVEs (was 29);
  takes ~4 minutes due to NVD anonymous rate limit.

---

## SKELETONKEY v0.8.0 — 3 new 2025/2026 CVEs

Closes the 2025 coverage gap. Three new modules from CVEs disclosed
2025–2026, all with public PoC code we ported into proper
SKELETONKEY modules:

### CVE-2025-32463 — `sudo_chwoot` (Stratascale)

Critical (CVSS 9.3) sudo logic bug: `sudo --chroot=<DIR>` chroots
into a user-controlled directory before completing authorization +
resolves user/group via NSS inside the chroot. Plant a malicious
`libnss_*.so` + an `nsswitch.conf` that points to it; sudo dlopens
the .so as root, ctor fires, root shell. Affects sudo 1.9.14 to
1.9.17p0; fixed in 1.9.17p1 (which deprecated --chroot entirely).
`arch_support: any` (pure userspace).

### CVE-2025-6019 — `udisks_libblockdev` (Qualys)

udisks2 + libblockdev SUID-on-mount chain. libblockdev's internal
filesystem-resize/repair mount path omits `MS_NOSUID` and
`MS_NODEV`. udisks2 gates the operation on polkit's
`org.freedesktop.UDisks2.modify-device` action, which is
`allow_active=yes` by default → any active console session user can
trigger it without a password. Build an ext4 image with a SUID-root
shell inside, get udisks to mount it, execute the SUID shell.
Affects libblockdev < 3.3.1, udisks2 < 2.10.2. `arch_support: any`.

### CVE-2026-43494 — `pintheft` (V12 Security)

Linux kernel RDS zerocopy double-free. `rds_message_zcopy_from_user()`
pins user pages one at a time; if a later page faults, the error
unwind drops the already-pinned pages, but the msg's scatterlist
cleanup drops them AGAIN. Each failed `sendmsg(MSG_ZEROCOPY)` leaks
one pin refcount. Chain via io_uring fixed buffers to overwrite the
page cache of a readable SUID binary → execve → root. Mainline fix
commit `0cebaccef3ac` (posted to netdev 2026-05-05). Among common
distros only **Arch Linux** autoloads the rds module — Ubuntu /
Debian / Fedora / RHEL / Alma / Rocky / Oracle Linux either don't
build it or blacklist autoload. `detect()` correctly returns OK
on non-Arch hosts (RDS unreachable from userland). 🟡 PRIMITIVE
status: primitive fires; full cred-overwrite via the shared
modprobe_path finisher requires `--full-chain` on x86_64.

### Corpus growth

| | v0.7.1 | v0.8.0 |
|---|---|---|
| Modules registered | 31 | 34 |
| Distinct CVEs | 26 | 29 |
| 2025-CVE coverage | 0 | 2 |
| Detection rules embedded | 119 | 131 |
| Arch-independent (`any`) | 4 | 6 |
| CISA KEV-listed | 10 | 10 (new ones not yet KEV'd) |
| VM-verified | 22 | 22 |

### Other changes

- `tools/refresh-cve-metadata.py` — added curl fallback for the
  CISA KEV CSV fetch (Python's urlopen was hitting timeouts against
  CISA's HTTP/2 endpoint).
- `tools/verify-vm/targets.yaml` — entries for the 3 new modules
  with honest "no Vagrant box covers this yet" notes for
  pintheft (needs Arch) and udisks_libblockdev (needs active
  console session + udisks2 installed).

---

## SKELETONKEY v0.7.1 — arm64-static binary + per-module arch_support

Point release on top of v0.7.0. Two additions:

1. **`skeletonkey-arm64-static`** is now published alongside the
   existing x86_64-static binary. Built native-arm64 in Alpine via
   GitHub's `ubuntu-24.04-arm` runner pool. Works on Raspberry Pi 4+,
   Apple Silicon Linux VMs, AWS Graviton, Oracle Ampere, Hetzner ARM,
   and any other aarch64 Linux. `install.sh` auto-picks it.

2. **`arch_support` per module** — a new field on
   `struct skeletonkey_module` that honestly labels which architectures
   the `exploit()` body has been verified on. Three categories:

   - **`any`** (4 modules): pwnkit, sudo_samedit, sudoedit_editor,
     pack2theroot. Purely userspace; arch-independent.
   - **`x86_64`** (1 module): entrybleed. KPTI prefetchnta side-channel;
     x86-only by physics (ARM uses TTBR_EL0/EL1 split, not CR3).
     Already gated in source — returns PRECOND_FAIL on non-x86_64.
   - **`x86_64+unverified-arm64`** (26 modules): kernel-exploitation
     code that hasn't been verified on arm64 yet. `detect()` works
     everywhere (it just reads `ctx->host`); the `exploit()` body uses
     primitives (msg_msg sprays, ROP-style finishers, specific struct
     offsets) that are likely portable to aarch64 but unproven.

   `--list` adds an ARCH column; `--module-info` adds an `arch support:`
   line; `--scan --json` adds an `arch_support` field per module.

**What an arm64 user gets today:** the full detection/triage workflow
works as well as on x86_64 (`--scan`, `--explain`, `--module-info`,
`--detect-rules`, `--auto --dry-run`). Four exploit modules
(`pwnkit`, `sudo_samedit`, `sudoedit_editor`, `pack2theroot`) will fire
end-to-end. The remaining 26 modules currently mark themselves as
"x86_64 verified; arm64 untested" — the bug class is generic but the
exploitation hasn't been confirmed. Future arm64-Vagrant verification
sweeps will promote modules to `any` as they're confirmed.

---

### From v0.7.0 — empirical verification + operator briefing

The headline change since v0.6.0: **22 of 26 CVEs are now empirically
confirmed against real Linux kernels in VMs**, with verification records
baked into the binary and surfaced in `--list`, `--module-info`, and
`--explain`. The four still-unverified entries (`vmwgfx`, `dirty_cow`,
`dirtydecrypt`, `fragnesia`) are blocked by their target environment
(VMware-only, ≤4.4 kernel, Linux 7.0 not yet shipping), not by missing
code — see
[`tools/verify-vm/targets.yaml`](https://github.com/KaraZajac/SKELETONKEY/blob/main/tools/verify-vm/targets.yaml)
for the rationale.

### Install

Pre-built binaries below (x86_64 dynamic, x86_64 static-musl, arm64
dynamic; all checksum-verified). Recommended for new installs:

```bash
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh
skeletonkey --version
```

Static-musl x86_64 is the default — works back to glibc 2.17, no
library dependencies.

### What's in this release

**Empirical verification (the big one)**
- `tools/verify-vm/` — Vagrant + Parallels scaffold. Boots
  known-vulnerable kernels (stock distro or mainline via
  `kernel.ubuntu.com/mainline/`), runs `--explain --active` per module,
  records match/mismatch as JSONL.
- 22 modules confirmed end-to-end across Ubuntu 18.04 / 20.04 / 22.04 +
  Debian 11 / 12 + mainline kernels 5.15.5 / 6.1.10.
- Per-module `verified_on[]` table baked into the binary. `--list` adds
  a `VFY` column showing ✓ per verified module; footer prints
  `31 modules registered · 10 in CISA KEV (★) · 22 empirically verified
  in real VMs (✓)`.
- `--module-info <name>` adds a `--- verified on ---` section.
- `--explain <name>` adds a `VERIFIED ON` section.

**`--explain MODULE` — one-page operator briefing**

A single command renders, for any module: CVE / CWE / MITRE ATT&CK /
CISA KEV status, host fingerprint, **live `detect()` trace** with
verdict and interpretation, **OPSEC footprint** (what an exploit
would leave on this host), detection-rule coverage matrix, and
verification records. Paste-ready for triage tickets and SOC handoffs.

**CVE metadata pipeline**

`tools/refresh-cve-metadata.py` fetches CISA's Known Exploited
Vulnerabilities catalog + NVD CWE classifications, generates
`docs/CVE_METADATA.json` + `docs/KEV_CROSSREF.md` + the in-binary
lookup table. **10 of 26 modules cover KEV-listed CVEs.** MITRE ATT&CK
technique mapping (T1068 by default; T1611 for container escapes;
T1082 for kernel info leaks). All surfaced in `--list` (★ column),
`--module-info`, `--explain`, and `--scan --json` (new `triage`
sub-object per module).

**Per-module OPSEC notes**

Every module's struct now carries an `opsec_notes` paragraph describing
the runtime telemetry footprint: file artifacts, dmesg signatures,
syscall observables, network activity, persistence side effects,
cleanup behavior. Grounded in source + existing detection rules — the
inverse of what the auditd/sigma/yara/falco rules look for. Surfaced
in `--module-info` (text + JSON) and `--explain`.

**119 detection rules across all 4 SIEM formats**

Previously: auditd everywhere, sigma on top-10, yara/falco only on a
handful. Now: 30/31 auditd, 31/31 sigma, 28/31 yara, 30/31 falco
(the 3 remaining gaps are intentional skips — `entrybleed` is a pure
timing side-channel with no syscall/file footprint;
`ptrace_traceme` and `sudo_samedit` are pure-memory races with no
on-disk artifacts).

**Test harness**

88 tests on every push: 33 kernel_range / host-fingerprint unit tests
(`tests/test_kernel_range.c` — boundary conditions, NULL safety,
multi-LTS, mainline-only) + 55 `detect()` integration tests
(`tests/test_detect.c` — synthetic host fingerprints across 26
modules). Coverage report at the end identifies any modules without
direct test rows.

**`core/host.c` shared host-fingerprint refactor**

One probe of kernel / arch / distro / userns gates / apparmor /
selinux / lockdown / sudo + polkit versions at startup. Every
module's `detect()` consumes `ctx->host`. Adds `meltdown_mitigation[]`
passthrough so `entrybleed` can distinguish "Not affected" (CPU
immune; OK) from "Mitigation: PTI" (KPTI on; vulnerable to
EntryBleed) without re-reading sysfs.

**kernel_range drift detector**

`tools/refresh-kernel-ranges.py` polls Debian's security tracker and
reports drift between the embedded `kernel_patched_from` tables and
what Debian actually ships. Already used to apply 9 corpus fixes in
v0.7.0; 9 more `TOO_TIGHT` findings pending per-commit verification.

**Marketing-grade landing page**

[karazajac.github.io/SKELETONKEY](https://karazajac.github.io/SKELETONKEY/)
— animated hero, `--explain` showcase with line-by-line typed terminal,
bento-grid features, KEV / verification stat chips. New Open Graph
card renders correctly on Twitter/LinkedIn/Slack/Discord.

### Real findings from the verifier

A handful of cases that show the project's "verified-vs-claimed bar"
thesis paying off in real time:

- **`dirty_pipe` on Ubuntu 22.04 (5.15.0-91-generic)** — version-only
  check would say VULNERABLE (5.15.0 < 5.15.25 backport in our table),
  but Ubuntu has silently backported the fix into the -91 patch level.
  `--active` correctly identified the primitive as blocked → OK. Only
  an empirical probe can tell.
- **`af_packet` on Ubuntu 18.04 (4.15.0-213-generic)** — our target
  expectation was wrong; 4.15 is post-fix. Caught + corrected by the
  verifier sweep.
- **`sudoedit_editor` on Ubuntu 22.04** — sudo 1.9.9 is the vulnerable
  version, but the default vagrant user has no sudoers grant to abuse.
  `detect()` correctly returns PRECOND_FAIL ("vuln version present, no
  grant to abuse").

### Coverage by audience

- **Red team**: `--auto` ranks vulnerable modules by safety + runs the
  safest, OPSEC notes per exploit, JSON for pipelines, no telemetry.
- **Blue team**: 119 detection rules in all 4 SIEM formats, CISA KEV
  prioritization, MITRE ATT&CK + CWE annotated, `--explain` triage
  briefings.
- **Researchers**: Source is the docs. CVE metadata sourced from
  federal databases. `--explain` shows the reasoning chain. 22 VM
  confirmations for trust.
- **Sysadmins**: `--scan` works without sudo. Static-musl binary
  drops on any Linux. JSON output for CI gates.

### Compatibility

- Default install: static-musl x86_64 — works on every Linux back to
  glibc 2.17 (RHEL 7, Debian 9, Ubuntu 14.04+, Alpine, anything).
- Also published: dynamic x86_64 (faster, modern glibc only) and
  dynamic arm64 (Raspberry Pi 4+, Apple Silicon Linux VMs, ARM
  servers).

### Authorized testing only

SKELETONKEY runs real exploits. By using it you assert you have
explicit authorization to test the target system. See
[`docs/ETHICS.md`](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/ETHICS.md).

### Links

- [CVE inventory](https://github.com/KaraZajac/SKELETONKEY/blob/main/CVES.md)
- [Verification records](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/VERIFICATIONS.jsonl)
- [KEV cross-reference](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/KEV_CROSSREF.md)
- [Detection playbook](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/DETECTION_PLAYBOOK.md)
- [Architecture](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/ARCHITECTURE.md)
- [Roadmap](https://github.com/KaraZajac/SKELETONKEY/blob/main/ROADMAP.md)
