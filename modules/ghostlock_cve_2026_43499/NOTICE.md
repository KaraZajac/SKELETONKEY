# NOTICE — ghostlock (CVE-2026-43499)

## Vulnerability

**CVE-2026-43499** — "GhostLock", a **race-condition use-after-free** on
kernel **stack** memory in the Linux rtmutex / futex requeue-PI path
(`kernel/locking/rtmutex.c`). On the deadlock-rollback path,
`remove_waiter()` operates on `current` instead of the actual waiter task
while unwinding a proxy lock in `rt_mutex_start_proxy_lock()` (reached from
`futex_requeue()`); a concurrent PI-chain priority walk driven via
`sched_setattr()` on another CPU clears `pi_blocked_on` on the wrong task and
leaves an on-stack `struct rt_mutex_waiter` dangling → UAF when the kernel
later rotates the rbtree over the reused stack frame.

The bug is reachable by **any unprivileged local user** (CVSS 7.8, PR:L) —
`futex(2)` + `sched_setattr(2)`, no capability, no user namespace, no special
config beyond `CONFIG_FUTEX_PI` (universally enabled). It has existed since
PI-futex requeue landed in **2.6.39** — ~15 years across every distribution.
NVD class: **CWE-416** (Use After Free), with a **CWE-362** race root cause.
**Not** in CISA KEV (brand new).

## Research credit

- **Discovery, research, and public PoC** by **VEGA / Nebula Security**
  (`@nebusecurity`, <https://nebusec.ai>), published as "IonStack part II:
  GhostLock" (<https://nebusec.ai/research/ionstack-part-2/>). Exploit code:
  <https://github.com/NebuSec/CyberMeowfia> (`IonStack/CVE-2026-43499`,
  Apache-2.0). Awarded **$92,337** in Google's kernelCTF for a ~97%-stable
  privilege escalation / container escape. SKELETONKEY's trigger
  reconstruction is informed by the public PoC's requeue-PI cycle shape only
  — no KernelSnitch offsets, forged-waiter field layout, or ROP / cred-patch
  arithmetic is reused.
- **Introduced** with PI-futex requeue in **2.6.39** (commit
  `8161239a8bcc`).
- **Fixed upstream** by commit
  `3bfdc63936dd4773109b7b8c280c0f3b5ae7d349` ("rtmutex: Use waiter::task
  instead of current in remove_waiter()", Keenan Dong / Thomas Gleixner),
  merged for **7.1-rc1**; stable backports **7.0.4 / 6.18.27 / 6.12.86 /
  6.6.140 / 6.1.175**.
- Authoritative backport versions: the Linux kernel CNA record
  (<https://cveawg.mitre.org/api/cve/CVE-2026-43499>,
  `git.kernel.org/stable/c/<hash>`), corroborated by the Debian
  (<https://security-tracker.debian.org/tracker/CVE-2026-43499>), Ubuntu, and
  SUSE trackers. The **5.15 / 5.10 / 5.4 / 4.19** LTS branches are affected
  with no upstream stable fix published at time of writing.

All credit for finding, analysing, and exploiting this bug belongs to VEGA /
Nebula Security and to the upstream maintainers who fixed it. SKELETONKEY is
the bundling and bookkeeping layer only.

## SKELETONKEY role

🟡 **Trigger (reconstructed) — reachability-only, not VM-verified.** This is
the corpus's first rtmutex / futex-PI module and its cleanest example of a
kernel-**stack** UAF (every other UAF in the corpus is heap/slab). Shipped on
the same "fire the bug class and stop" contract as `stackrot`
(CVE-2023-3269), `nft_catchall` (CVE-2026-23111), and `bad_epoll`
(CVE-2026-46242).

`detect()` is a pure kernel-version gate (vulnerable iff `>= 2.6.39` and below
the on-branch fix; backports 7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175,
7.1+ inherits mainline; 5.15/5.10/5.4/4.19 affected with no upstream fix) — no
userns or CONFIG probe (`CONFIG_FUTEX_PI` assumed, near-universal).
`exploit()` forks an isolated child that confirms the `-EDEADLK`
`remove_waiter()` rollback path is reachable (deterministic, safe) and then
exercises the actual race a hard-bounded 24 iterations / 2 s with a
sibling-CPU `sched_setattr(SCHED_BATCH)` storm, and stops.

It is **deliberately under-driven**: a won race corrupts the kernel stack and
drives a near-arbitrary pointer write (near-certain panic), so the module does
not widen the `copy_from_user` window, does not spray/reoccupy the freed
frame, and does not bundle the KernelSnitch leak → forged on-stack
`rt_mutex_waiter` → fops/configfs/ashmem/pipe R/W → cred-patch root-pop
(Android/Pixel-specific, per-build offsets). The trigger is reconstructed from
the public PoC, not VM-verified — it never claims root it did not get. It
carries the lowest `--auto` safety rank in the corpus.
