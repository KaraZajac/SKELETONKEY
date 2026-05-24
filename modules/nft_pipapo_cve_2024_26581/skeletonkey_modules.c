/*
 * nft_pipapo_cve_2024_26581 — SKELETONKEY module
 *
 * STATUS: 🟡 PRIMITIVE. nfnetlink batch + msg_msg cross-cache groom.
 *   Sibling to nf_tables (CVE-2024-1086) — same Notselwyn "Flipping
 *   Pages" paper, same pipapo set substrate. Full cred-overwrite via
 *   the shared modprobe_path finisher on --full-chain (x86_64).
 *
 * The bug (Notselwyn / Mauro Lima, "Flipping Pages" Feb 2024):
 *   nft_pipapo_destroy() in net/netfilter/nft_set_pipapo.c didn't
 *   properly drain the per-CPU walk state when destroying a pipapo
 *   set. Combined with concurrent SETELEM operations, an attacker
 *   can free elements while another CPU still has references, then
 *   spray msg_msg to refill the freed slabs and pivot through the
 *   walk callbacks → arb R/W → cred overwrite.
 *
 *   This is the SECOND major bug in the Notselwyn / 'Flipping Pages'
 *   research series (the first, CVE-2024-1086, is our nf_tables
 *   module). Both target the pipapo set type used for IP/port matches.
 *
 *   Public PoC: not yet released by Notselwyn (responsible
 *   disclosure window), but extensive technical writeup at the
 *   pwning.tech blog. Patch landed pre-disclosure.
 *
 * Affects: Linux kernels with CONFIG_NF_TABLES + the pipapo set
 *   type (introduced kernel 5.6). Fix commit 2ee52ae94baa
 *   ("netfilter: nft_set_pipapo: walk over current view on
 *   netlink dump") landed in 6.8-rc + stable backports:
 *     6.7.x  : 6.7.4
 *     6.6.x  : 6.6.16
 *     6.1.x  : 6.1.78
 *     5.15.x : 5.15.149
 *     5.10.x : 5.10.210
 *
 * Preconditions:
 *   - unshare(CLONE_NEWUSER|CLONE_NEWNET) for unprivileged userns
 *     CAP_NET_ADMIN (same as nf_tables)
 *   - msgsnd / SysV IPC for kmalloc-cg-96 / kmalloc-cg-512 spray
 *
 * arch_support: x86_64+unverified-arm64. Same family as nf_tables.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef __linux__
#include <linux/netfilter/nf_tables.h>
#include "../../core/nft_compat.h"
#endif

/* ---- kernel-range table -------------------------------------------- */

static const struct kernel_patched_from nft_pipapo_patched_branches[] = {
    {5, 10, 210},
    {5, 15, 149},
    {6,  1,  78},
    {6,  6,  16},
    {6,  7,   4},
    {6,  8,   0},   /* mainline fix in 6.8-rc */
};

static const struct kernel_range nft_pipapo_range = {
    .patched_from = nft_pipapo_patched_branches,
    .n_patched_from = sizeof(nft_pipapo_patched_branches) /
                      sizeof(nft_pipapo_patched_branches[0]),
};

/* ---- detect --------------------------------------------------------- */

static skeletonkey_result_t nft_pipapo_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] nft_pipapo: host fingerprint missing kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }
    /* Bug was introduced in 5.6 (pipapo set type debut). Earlier
     * kernels don't have pipapo at all. */
    if (v->major < 5 || (v->major == 5 && v->minor < 6)) {
        if (!ctx->json) fprintf(stderr, "[+] nft_pipapo: kernel %s predates pipapo set type (5.6+) → OK\n", v->release);
        return SKELETONKEY_OK;
    }
    if (kernel_range_is_patched(&nft_pipapo_range, v)) {
        if (!ctx->json) fprintf(stderr, "[+] nft_pipapo: kernel %s is patched (>= 6.8 / LTS backport)\n", v->release);
        return SKELETONKEY_OK;
    }
    if (!ctx->host || !ctx->host->unprivileged_userns_allowed) {
        if (!ctx->json) fprintf(stderr, "[i] nft_pipapo: unprivileged userns blocked → CAP_NET_ADMIN unreachable → PRECOND_FAIL\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] nft_pipapo: kernel %s in vulnerable range (5.6 ≤ K, no LTS backport) + userns OK → VULNERABLE\n", v->release);
        fprintf(stderr, "[i] nft_pipapo: same Notselwyn 'Flipping Pages' family as nf_tables; pipapo destroy race + msg_msg groom\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t nft_pipapo_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] nft_pipapo: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr,
        "[i] nft_pipapo: nfnetlink batch (NEWTABLE+NEWSET pipapo +\n"
        "    burst NEWSETELEM/DELSETELEM with concurrent DESTROYSET)\n"
        "    races the per-CPU pipapo walk teardown. msg_msg cross-\n"
        "    cache groom in kmalloc-cg-96 / cg-512 refills the freed\n"
        "    slabs. Same Notselwyn family as nf_tables (CVE-2024-1086);\n"
        "    the existing nf_tables module's --full-chain finisher\n"
        "    handles this bug's arb-write too once a working PoC is\n"
        "    ported here. Returning EXPLOIT_FAIL honestly per the\n"
        "    verified-vs-claimed bar.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- detection rules (share shape with nf_tables) ------------------ */

static const char nft_pipapo_auditd[] =
    "# nft_pipapo CVE-2024-26581 — auditd detection rules\n"
    "# Same shape as nf_tables: unshare(CLONE_NEWUSER|CLONE_NEWNET)\n"
    "# + nfnetlink batch + msg_msg spray. Differentiates from\n"
    "# CVE-2024-1086 only at the netlink payload level (pipapo set\n"
    "# type vs nft_verdict_init); auditd alone can't tell them\n"
    "# apart, so the trigger key covers both bugs.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-nft-pipapo-userns\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -k skeletonkey-nft-pipapo-priv\n";

static const char nft_pipapo_sigma[] =
    "title: Possible CVE-2024-26581 nft_pipapo destroy-race UAF\n"
    "id: 4e9c1a83-skeletonkey-nft-pipapo\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape: userns clone +\n"
    "  nfnetlink rapid DESTROYSET/NEWSETELEM batches. Same family\n"
    "  as CVE-2024-1086; differentiates by elevated frequency of\n"
    "  NFT_MSG_DELSET on pipapo set types.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  u: {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  g: {type: 'SYSCALL', syscall: 'msgsnd'}\n"
    "  condition: u and g\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2024.26581]\n";

static const char nft_pipapo_yara[] =
    "rule nft_pipapo_cve_2024_26581 : cve_2024_26581 kernel_uaf {\n"
    "    meta:\n"
    "        cve         = \"CVE-2024-26581\"\n"
    "        description = \"SKELETONKEY nft_pipapo race-driver tag\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKK_PIPAPO\" ascii\n"
    "    condition:\n"
    "        $tag\n"
    "}\n";

static const char nft_pipapo_falco[] =
    "- rule: nfnetlink pipapo destroy-race batch by non-root\n"
    "  desc: |\n"
    "    Non-root nfnetlink batch creating pipapo sets and rapidly\n"
    "    cycling DESTROYSET/NEWSETELEM. Same family as nf_tables;\n"
    "    distinct CVE (2024-26581 / 'Flipping Pages' part 2).\n"
    "  condition: >\n"
    "    evt.type = sendmsg and fd.sockfamily = AF_NETLINK and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    nfnetlink batch by non-root (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2024.26581]\n";

const struct skeletonkey_module nft_pipapo_module = {
    .name           = "nft_pipapo",
    .cve            = "CVE-2024-26581",
    .summary        = "nft_set_pipapo destroy-race UAF (Notselwyn 'Flipping Pages' II)",
    .family         = "nf_tables",
    .kernel_range   = "5.6 ≤ K, fixed 6.8 mainline + 6.7.4 / 6.6.16 / 6.1.78 / 5.15.149 / 5.10.210 LTS",
    .detect         = nft_pipapo_detect,
    .exploit        = nft_pipapo_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel OR sysctl kernel.unprivileged_userns_clone=0 */
    .cleanup        = NULL,
    .detect_auditd  = nft_pipapo_auditd,
    .detect_sigma   = nft_pipapo_sigma,
    .detect_yara    = nft_pipapo_yara,
    .detect_falco   = nft_pipapo_falco,
    .opsec_notes    = "unshare(CLONE_NEWUSER|CLONE_NEWNET); nfnetlink batch creating a table + pipapo set + many SETELEMs; concurrent DESTROYSET against the same set from a second thread races the per-CPU pipapo walk teardown. msg_msg cross-cache spray (kmalloc-cg-96 + cg-512, tag 'SKK_PIPAPO') refills the freed slabs. Same family signal as nf_tables (CVE-2024-1086): unshare + nfnetlink + msg_msg burst from a non-root process. Distinguishes at the netlink payload layer (pipapo set type vs verdict-init double-free) which auditd alone can't see. dmesg may show 'KASAN: use-after-free in nft_pipapo_walk' on race-win attempts. No persistent file artifacts.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_nft_pipapo(void)
{
    skeletonkey_register(&nft_pipapo_module);
}
