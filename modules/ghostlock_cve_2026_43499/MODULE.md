# ghostlock — CVE-2026-43499

"GhostLock" — a race-condition use-after-free on **kernel stack** memory in
the Linux rtmutex / futex requeue-PI code path (`kernel/locking/rtmutex.c`),
reachable by **any unprivileged local user** (CVSS PR:L). No user namespace,
no capability, no special `CONFIG` beyond `CONFIG_FUTEX_PI` (universally
enabled). It has existed since PI-futex requeue landed — **~15 years, across
every distribution** — which is what makes it remarkable.

## The bug

On the deadlock-rollback path, `remove_waiter()` operates on `current`
instead of the actual waiter task while unwinding a proxy lock in
`rt_mutex_start_proxy_lock()` — reached from `futex_requeue()`. If a
concurrent PI-chain priority walk (driven from another CPU via
`sched_setattr()`) runs at that instant, `pi_blocked_on` is cleared on the
**wrong** task and an on-stack `struct rt_mutex_waiter` is left dangling in a
task's waiter / pi tree. When the kernel later rotates that rbtree over the
(now-reused) stack frame, the forged node fields become a controlled kernel
write → use-after-free.

The public research + PoC ("IonStack part II: GhostLock", VEGA / Nebula
Security) builds the requeue-PI cycle so `FUTEX_CMP_REQUEUE_PI` hits
`-EDEADLK` (the rollback) while a sibling-core consumer thread hammers
`sched_setattr(SCHED_BATCH)` on the waiter's tid to win the race. A separate
full Android/Pixel LPE then forges the on-stack `rt_mutex_waiter` on a leaked
kernel page (the "KernelSnitch" futex-bucket timing side channel), overwrites
a `struct file` `f_op` → configfs/ashmem arbitrary R/W → pipe physical R/W →
cred patch → root. ~**97% stable** on kernelCTF; Google awarded **$92,337**.

## Affected range

| | |
|---|---|
| Introduced | PI-futex requeue — **2.6.39** (commit `8161239a8bcc`) |
| Fixed upstream | commit `3bfdc63936dd` ("rtmutex: Use waiter::task instead of current in remove_waiter()") — merged **7.1-rc1** |
| Stable backports | **7.0.4** · 6.18.27 · **6.12.86** (LTS) · **6.6.140** (LTS) · **6.1.175** (LTS) |
| Affected, no upstream fix | **5.15.x / 5.10.x / 5.4.x / 4.19.x** (kernel CNA lists no stable fix) |
| Not affected | < 2.6.39 (predates PI-futex requeue) |
| NVD class | CWE-416 (Use After Free) via CWE-362 (race); CVSS 7.8, PR:L |
| CISA KEV | no (brand new) |

The `kernel_range` table carries one entry per backported branch;
`kernel_range_is_patched()` marks any branch strictly newer than all of them
(7.1+) patched-via-mainline and everything below the on-branch threshold
vulnerable — including the 5.x LTS lines that have no published fix. Extend
the table as more branches backport (the drift checker flags them). Source:
the Linux kernel CNA record (`git.kernel.org/stable/c/<hash>`), corroborated
by the Debian / Ubuntu / SUSE trackers.

## Trigger / detection

`detect()` is a **pure version gate** — no active probe, because there is no
cheap, safe way to distinguish vulnerable from patched without winning the
race. It returns `OK` below 2.6.39 or on a patched kernel, and `VULNERABLE`
in range. `CONFIG_FUTEX_PI` is a (near-universal) precondition detect()
**assumes** rather than probes; there is no userns / capability precondition
(any local user — CVSS PR:L).

`exploit()` forks an isolated child and runs two phases:

- **(A) deterministic + safe** — builds the requeue-PI cycle (a waiter
  holding a "chain" PI-futex and parked in `FUTEX_WAIT_REQUEUE_PI`; an owner
  holding the "target" PI-futex and blocked on the chain) and fires
  `FUTEX_CMP_REQUEUE_PI`, confirming the kernel returns **-EDEADLK**. That
  proves the `remove_waiter()` rollback path — where the bug lives — is
  reachable here. Without a concurrent priority walk the rollback is the
  kernel's normal, correct deadlock rejection: it creates no dangling
  pointer, so this phase is safe on any kernel. *(Validated on real hardware:
  the cycle returns `-EDEADLK` deterministically.)*
- **(B) hard-bounded window exercise** — repeats (A) a small, wall-clock-
  capped number of times (24 iterations / 2 s) with a sibling-CPU
  `sched_setattr(SCHED_BATCH)` storm on the waiter's tid, overlapping the
  priority walk with the rollback (the actual race). Then it stops.

It is **deliberately under-driven**. A *won* race corrupts the kernel
**stack** and drives a near-arbitrary pointer write — near-certain panic on a
vulnerable host. So this module does **not** widen the `copy_from_user`
window (no memfd / `PUNCH_HOLE`), does **not** spray or reoccupy the freed
stack frame, and does **not** bundle the KernelSnitch leak → forged-waiter →
fops/configfs/ashmem/pipe R/W → cred-patch chain (Android/Pixel-specific,
per-build offsets). The trigger is **reconstructed from the public PoC and is
not VM-verified**. It returns `EXPLOIT_FAIL` and never claims root it did not
get.

Because a kernel race that corrupts the stack is the least predictable class
in the corpus, `ghostlock` carries the **lowest `--auto` safety rank** (11 —
just below `bad_epoll`), so `--auto` only reaches for it after every safer
vulnerable module.

## Detection — better than most kernel races, but read this

Unlike `bad_epoll` (whose epoll syscalls are indistinguishable from every
event loop), GhostLock has a **genuinely distinctive tell**: a futex
requeue-PI op (`FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`) returning
`-EDEADLK`, which glibc's requeue-PI usage inside `pthread_cond_wait` never
provokes, interleaved with `sched_setattr(SCHED_BATCH)` on a **sibling
thread** and `sched_setaffinity` CPU pinning. The catch: auditd/sigma see the
`futex` syscall but not its op-vs-return cheaply, and a bare `-S futex` watch
would flood any host. So:

- **auditd / sigma** anchor on the far rarer `sched_setattr` /
  `sched_setaffinity` drivers plus the post-exploitation euid-0 transition.
- **falco / eBPF** carries the high-fidelity rule (futex requeue-PI returns
  `EDEADLK` + sibling `sched_setattr`) — it can see the op and the return
  value.

There is no yara rule (in-kernel race, no file artifact). Tune the
`sched_setattr` anchor per environment — real-time and scheduler-tuning
daemons will false-positive.

## Fix / mitigation

Upgrade the kernel (>= 7.0.4 / 6.12.86 / 6.6.140 / 6.1.175 on-branch, or
7.1+). There is **no partial mitigation**: PI futexes cannot be disabled at
runtime, and no `unprivileged_userns_clone` / sysctl toggle closes this path.
`mitigate()` is `NULL` for that reason.

## Credit

Discovery, research, and the public PoC: **VEGA / Nebula Security**
(`@nebusecurity`, nebusec.ai). Upstream fix `3bfdc63936dd` (Keenan Dong /
Thomas Gleixner). See `NOTICE.md`.
