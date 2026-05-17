/*
 * nf_tables_cve_2024_1086 — IAMROOT module
 *
 * Netfilter nf_tables UAF when NFT_GOTO/NFT_JUMP verdicts coexist
 * with NFT_DROP/NFT_QUEUE. Triggers a double-free → cross-cache UAF
 * exploitable to arbitrary kernel R/W. Discovered and exploited in
 * January 2024; widely known as "Pumpkin's pipapo UAF" or just
 * "CVE-2024-1086".
 *
 * STATUS: 🔵 DETECT-ONLY (2026-05-16). Full exploit is a public PoC
 * by Notselwyn — porting it into the iamroot_module form is a
 * follow-up commit.
 *
 * Affected kernel ranges:
 *   Bug introduced in commit f1a2e44 (5.14) "netfilter: nf_tables:
 *     introduce nf_chain..."
 *   Fixed mainline 6.8-rc1 in commit f342de4 ("netfilter: nf_tables:
 *     reject QUEUE/DROP verdict parameters")
 *   Stable backports landed in 6.7.2, 6.6.13, 6.1.74, 5.15.149,
 *     5.10.210, 5.4.269
 *   So vulnerable if:
 *     - 5.14 <= K < 5.15 (no backport) — vulnerable
 *     - 5.15.x: K <= 5.15.148 — vulnerable
 *     - 5.10.x: K <= 5.10.209 — vulnerable
 *     - 5.4.x: K <= 5.4.268 — vulnerable
 *     - 6.0/6.1.x: K <= 6.1.73 — vulnerable
 *     - 6.2-6.5: no backport tags — assume vulnerable
 *     - 6.6.x: K <= 6.6.12 — vulnerable
 *     - 6.7.x: K <= 6.7.1 — vulnerable
 *     - 6.8+: patched
 *
 * Exploitation preconditions (which detect should also check):
 *   - CONFIG_USER_NS=y AND sysctl unprivileged_userns_clone=1 (or
 *     kernel.unprivileged_userns_clone default=1) so an unprivileged
 *     user can create a userns and become CAP_NET_ADMIN inside it
 *   - nf_tables module loaded or autoload-able (CONFIG_NF_TABLES=y/m)
 *
 * If user_ns is locked down (modern Ubuntu's
 * apparmor_restrict_unprivileged_userns), the trigger is unreachable
 * for unprivileged users even on a kernel-vulnerable host.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/wait.h>

/* Stable-branch backport thresholds — host is patched if on these
 * branches at or above the threshold patch, or on mainline >= 6.8. */
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

/* Best-effort check: can an unprivileged process clone a user
 * namespace? This is the gating capability for the exploit's
 * CAP_NET_ADMIN-in-userns trigger. Fork+unshare+exit to avoid
 * polluting our own namespace state. */
static int can_unshare_userns(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* try */
        if (unshare(CLONE_NEWUSER) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Check whether the nf_tables module is loaded OR can be auto-loaded.
 * /proc/modules tells us about loaded modules. For modules that aren't
 * loaded but are buildable, we rely on the kernel autoload via
 * setsockopt(SOL_NETLINK, NETLINK_NF_TABLES). Conservative: if not
 * loaded, assume autoload-able and report no info. */
static bool nf_tables_loaded(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        /* /proc/modules format: "<name> <size> <use_count> <by> <state> <addr>" */
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

    /* Vulnerable by version. Now check preconditions that affect
     * unprivileged reachability. */
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

    /* If user_ns is denied, the unprivileged-exploit path is closed.
     * (A root attacker would still trigger the bug, but root LPE-of-root
     * is not interesting.) */
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

static iamroot_result_t nf_tables_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] nf_tables: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY (see CVES.md).\n"
        "    Reference: Notselwyn's CVE-2024-1086 public PoC. The exploit\n"
        "    uses double-free → cross-cache UAF → arbitrary kernel R/W →\n"
        "    overwrite modprobe_path or current task's cred. Porting that\n"
        "    into iamroot_module form (with the userns + nft_set + nft_pipapo\n"
        "    setup boilerplate) is the next nf_tables commit.\n");
    return IAMROOT_PRECOND_FAIL;
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
