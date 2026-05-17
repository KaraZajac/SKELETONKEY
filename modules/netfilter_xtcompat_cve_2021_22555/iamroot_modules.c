/*
 * netfilter_xtcompat_cve_2021_22555 — IAMROOT module
 *
 * Heap-out-of-bounds in xt_compat_target_to_user(): the 32-bit
 * compat handler for iptables rule export wrote up to 4 bytes
 * beyond a heap allocation when copying rule names from kernel to
 * userspace. Exploitable via msg_msg slab cross-cache groom into
 * a kernel R/W primitive.
 *
 * Discovered by Andy Nguyen (Google), April 2021. Famous because
 * the bug existed since 2.6.19 (2006) — fifteen years of latent
 * vulnerability — and it works on default-config kernels with
 * unprivileged user_ns enabled (no special hardware or modules).
 *
 * STATUS: 🔵 DETECT-ONLY. Public PoC (Andy's "exploit.c") works
 * end-to-end with msg_msg + sk_buff sprays; porting is ~400 lines.
 *
 * Affected: kernel 2.6.19+ until backports landed:
 *   5.11.x : K >= 5.11.10
 *   5.10.x : K >= 5.10.27
 *   5.4.x  : K >= 5.4.110
 *   4.19.x : K >= 4.19.185
 *   4.14.x : K >= 4.14.230
 *   4.9.x  : K >= 4.9.266
 *   4.4.x  : K >= 4.4.266
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
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

static const struct kernel_patched_from netfilter_xtcompat_patched_branches[] = {
    {4,  4, 266},
    {4,  9, 266},
    {4, 14, 230},
    {4, 19, 185},
    {5,  4, 110},
    {5, 10,  27},
    {5, 11,  10},
    {5, 12,   0},   /* mainline (5.12-rc) */
};

static const struct kernel_range netfilter_xtcompat_range = {
    .patched_from = netfilter_xtcompat_patched_branches,
    .n_patched_from = sizeof(netfilter_xtcompat_patched_branches) /
                      sizeof(netfilter_xtcompat_patched_branches[0]),
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

static iamroot_result_t netfilter_xtcompat_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] netfilter_xtcompat: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: Andy Nguyen's public PoC\n"
        "    (~400 lines, msg_msg + sk_buff cross-cache groom). Porting\n"
        "    is a substantial follow-up — the exploit's heap-massage\n"
        "    sequence and cred-overwrite walk are the bulk.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char netfilter_xtcompat_auditd[] =
    "# CVE-2021-22555 — auditd detection rules\n"
    "# The exploit's hallmarks: unshare(USER|NET) chained with iptables\n"
    "# rule setup via setsockopt() and msgsnd/msgrcv heap-spray patterns.\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-xtcompat\n"
    "-a always,exit -F arch=b64 -S setsockopt -F a2=64 -k iamroot-xtcompat-iptopt\n"
    "-a always,exit -F arch=b64 -S msgsnd -k iamroot-xtcompat-msgmsg\n";

const struct iamroot_module netfilter_xtcompat_module = {
    .name           = "netfilter_xtcompat",
    .cve            = "CVE-2021-22555",
    .summary        = "iptables xt_compat_target_to_user heap-OOB write → cross-cache UAF → root",
    .family         = "netfilter_xtcompat",
    .kernel_range   = "2.6.19 ≤ K, fixed mainline 5.12; backports: 5.11.10 / 5.10.27 / 5.4.110 / 4.19.185 / 4.14.230 / 4.9.266 / 4.4.266",
    .detect         = netfilter_xtcompat_detect,
    .exploit        = netfilter_xtcompat_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; disable unprivileged_userns_clone */
    .cleanup        = NULL,
    .detect_auditd  = netfilter_xtcompat_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_netfilter_xtcompat(void)
{
    iamroot_register(&netfilter_xtcompat_module);
}
