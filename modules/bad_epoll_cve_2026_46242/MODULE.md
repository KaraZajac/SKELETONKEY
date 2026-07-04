# bad_epoll — CVE-2026-46242

"Bad Epoll" — a race-condition use-after-free in the Linux kernel epoll
subsystem (`fs/eventpoll.c`) reachable by **any unprivileged local user**.
No user namespace, no capability, no special `CONFIG` — `epoll_create1(2)`,
`epoll_ctl(2)`, and `close(2)` are available to everyone, which is what
makes this bug unusually dangerous.

## The bug

On the file-teardown path, `ep_remove()` clears `file->f_ep` under
`file->f_lock` but keeps **using** the file inside the same critical
section — the `hlist_del_rcu()` walk over the eventpoll's `refs` list and
the trailing `spin_unlock()`. A concurrent `__fput()` of a linked epoll
file can observe the transient `NULL` `f_ep`, skip
`eventpoll_release_file()`, and jump straight to `f_op->release`, freeing
a `struct eventpoll` that the first path is still walking →
**use-after-free** on a live kernel object.

The public exploit (Jaeyoung Chung, submitted to Google's kernelCTF)
arranges four epoll objects in two pairs — one pair drives the race, the
other is the victim — and converts the 8-byte UAF write into control of a
`struct file` via a **cross-cache** attack (the freed `eventpoll` slab
page is drained to the buddy allocator and reclaimed as pipe backing
buffers). From there it reads arbitrary kernel memory through
`/proc/self/fdinfo` and ROPs to a root shell. Roughly **99% reliable**
despite a race window only ~6 instructions wide; the racer widens it with
`close(dup())` storms that induce false-sharing on the file's `f_count`
cache line. It **rarely trips KASAN**, which is why the bug survived three
years and why it is hard to detect at runtime.

## Affected range

| | |
|---|---|
| Vulnerable path introduced | commit `58c9b016e128` — Linux **6.4** (2023-04-08) |
| Fixed upstream | commit `a6dc643c69311677c574a0f17a3f4d66a5f3744b` — merged for **7.1-rc1** (2026-04-24) |
| Stable backport | **7.0.13** (Debian forky `7.0.13-1` / sid `7.0.14-1`) |
| Still vulnerable at time of writing | trixie **6.12.x** (no backport yet); 6.6 LTS pending |
| Not affected | 6.1 and older (predate the bug — Debian: "vulnerable code not present") |
| NVD class | CWE-416 (Use After Free) via CWE-362 (race) |
| CISA KEV | no (brand new) |

Table threshold is a single `{7,0,13}` entry — `kernel_range_is_patched()`
treats 7.1+ as patched-via-mainline and everything in `[6.4, 7.0.13)` as
vulnerable, matching the Debian tracker. Add 6.6.x / 6.12.x rows when
those LTS backports land (`tools/refresh-kernel-ranges.py` flags them).

## Trigger / detection

`detect()` is a **pure version gate** — no active probe, because there is
no cheap, safe way to distinguish a vulnerable kernel from a patched one
without actually winning the race (the dangerous part). It returns `OK`
below 6.4 or on a patched kernel, and `VULNERABLE` in range. There is **no
`PRECOND_FAIL` userns path** the way `nft_catchall` has — epoll needs no
namespace, so there is no unprivileged-userns stopgap to report or to
harden with.

`exploit()` forks a CPU-pinned child that builds the epoll race pair (a
waiter eventpoll watching a target eventpoll) and exercises the
`ep_remove`-vs-`__fput` concurrent-close window a **hard-bounded** number
of times (48 attempts / 2 s), widening it with `close(dup())`
false-sharing storms, snapshots the `eventpoll`/`kmalloc-192` slab, and
returns `EXPLOIT_FAIL`.

It is **deliberately under-driven**. A *won* race frees a live
`struct eventpoll` — genuine kernel memory corruption that rarely trips
KASAN, so on a vulnerable production host a completed race can silently
destabilise the box rather than cleanly oops. This module therefore does
**not** grind the race to a win, does **not** perform the cross-cache
reclaim, and does **not** bundle the per-kernel `fdinfo` arbitrary-read +
ROP that lands root (per-build offsets refused). The trigger is
**reconstructed from the public kernelCTF PoC and is not VM-verified**. It
never claims root it did not get.

Because a kernel race is the least predictable class in the corpus — and
this one can corrupt memory invisibly — `bad_epoll` carries the **lowest
`--auto` safety rank** (see `module_safety_rank()` in `skeletonkey.c`), so
`--auto` only ever reaches for it after every safer vulnerable module.

## Detection is hard — read this before shipping the rules

Unlike most modules, `bad_epoll` has **no high-fidelity signature**.
`epoll_create1` / `epoll_ctl` / `close` is the steady-state behaviour of
nginx, systemd, and every language runtime's event loop; the exploit
looks identical and rarely trips KASAN. The shipped auditd/sigma/falco
rules therefore key on the **post-exploitation** tell — an unprivileged
process transitioning to euid 0 without a setuid `execve` — plus a
recommendation to monitor kernel logs for oops/BUG lines. Expect false
positives from legitimate privilege-management daemons and tune per
environment. There is no yara rule (no file artifact). Treat this module
as much as a *blue-team teaching case* — "here is a root LPE your existing
stack is nearly blind to" — as an offensive one.

## Fix / mitigation

Upgrade the kernel (>= 7.0.13, or 7.1+). There is **no partial
mitigation**: epoll cannot be disabled in practice, and no
`unprivileged_userns_clone` / sysctl toggle closes this path the way it
does for the netfilter bugs. `mitigate()` is `NULL` for that reason.

## Credit

Discovery, exploitation, and the public kernelCTF PoC:
**Jaeyoung Chung** (`J-jaeyoung`). Upstream fix `a6dc643c6931`. See
`NOTICE.md`.
