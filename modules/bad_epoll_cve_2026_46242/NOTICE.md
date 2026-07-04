# NOTICE — bad_epoll (CVE-2026-46242)

## Vulnerability

**CVE-2026-46242** — "Bad Epoll", a **race-condition use-after-free** in
the Linux kernel epoll subsystem (`fs/eventpoll.c`). On the file-teardown
path, `ep_remove()` clears `file->f_ep` under `file->f_lock` but continues
to use the file inside the critical section (`hlist_del_rcu()` over the
eventpoll `refs` list + `spin_unlock()`). A concurrent `__fput()` of a
linked epoll file observes the transient `NULL` `f_ep`, skips
`eventpoll_release_file()`, and proceeds to `f_op->release`, freeing a
`struct eventpoll` still in use → UAF.

The bug is reachable by **any unprivileged local user** — `epoll_create1`,
`epoll_ctl`, and `close` require no capability, no user namespace, and no
special kernel config. Exploitation converts the 8-byte UAF write into
control of a `struct file` via a cross-cache attack, gains arbitrary
kernel read through `/proc/self/fdinfo`, and ROPs to a root shell —
roughly 99% reliable despite a ~6-instruction race window. It also affects
Android. NVD class: **CWE-416** (Use After Free), with a **CWE-362** race
root cause. **Not** in CISA KEV (brand new).

## Research credit

- **Discovery, exploitation, and public PoC** by **Jaeyoung Chung**
  (GitHub `J-jaeyoung`), submitted as a zero-day to **Google's kernelCTF**
  program. Repository: <https://github.com/J-jaeyoung/bad-epoll> and the
  kernelCTF submission under
  `J-jaeyoung/security-research` (`CVE-2026-46242_lts_cos`, target
  `lts-6.12.67`). SKELETONKEY's trigger reconstruction is informed by that
  public PoC (the epoll object graph and the `ep_remove`-vs-`__fput`
  close-race shape only — no offsets or ROP are reused).
- **Introduced** by commit `58c9b016e128` (Linux 6.4, 2023-04-08).
- **Fixed upstream** by commit
  `a6dc643c69311677c574a0f17a3f4d66a5f3744b`, merged for **7.1-rc1**
  (2026-04-24); stable backport **7.0.13**.
- Debian security tracker (authoritative backport versions):
  <https://security-tracker.debian.org/tracker/CVE-2026-46242> — forky
  `7.0.13-1` / sid `7.0.14-1` fixed; trixie 6.12.x still vulnerable at time
  of writing; bookworm 6.1 and bullseye 5.10 "not affected — vulnerable
  code not present".

All credit for finding, analysing, and exploiting this bug belongs to
Jaeyoung Chung and to the upstream maintainers who fixed it. SKELETONKEY
is the bundling and bookkeeping layer only.

## SKELETONKEY role

🟡 **Trigger (reconstructed) — primitive-only, not VM-verified.** This is
the corpus's first epoll / VFS-file-teardown module and its cleanest
example of an SMP kernel race, shipped on the same "fire the bug class and
stop" contract as `stackrot` (CVE-2023-3269) and `nft_catchall`
(CVE-2026-23111).

`detect()` is a pure kernel-version gate (vulnerable iff `>= 6.4` and below
the fix on-branch; stable backport 7.0.13, 7.1+ inherits; 6.1/5.10 not
affected) — no userns or CONFIG precondition, because none is required.
`exploit()` forks a CPU-pinned child that builds the epoll race pair and
exercises the `ep_remove`-vs-`__fput` concurrent-close window a
hard-bounded number of times (48 attempts / 2 s), widening it with
`close(dup())` false-sharing storms, snapshots the eventpoll slab, and
returns `EXPLOIT_FAIL`.

It is **deliberately under-driven**: a won race frees a live
`struct eventpoll` (real corruption that rarely trips KASAN), so the module
does not grind the race to a win, does not perform the cross-cache reclaim,
and does not bundle the `/proc/self/fdinfo` arbitrary-read + ROP root-pop
(per-build offsets refused). The trigger is reconstructed from the public
kernelCTF PoC, not VM-verified — it never claims root it did not get. It
carries the lowest `--auto` safety rank in the corpus.
