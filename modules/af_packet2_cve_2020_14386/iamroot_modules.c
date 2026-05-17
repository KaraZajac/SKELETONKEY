/*
 * af_packet2_cve_2020_14386 — IAMROOT module
 *
 * AF_PACKET tpacket_rcv() VLAN tag parsing integer underflow → heap
 * write-before-allocation. Different bug from CVE-2017-7308 — same
 * subsystem, different code path (rx side rather than ring setup),
 * later introduction. Discovered by Or Cohen (2020).
 *
 * STATUS: 🔵 DETECT-ONLY. Or Cohen's public PoC works end-to-end;
 * porting follows the same shape as CVE-2017-7308.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

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

static iamroot_result_t af_packet2_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] af_packet2: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: Or Cohen's PoC.\n"
        "    Exploit shape: unshare userns → AF_PACKET socket → setsockopt\n"
        "    TPACKET_V2 ring + crafted VLAN-tagged frame → heap underflow →\n"
        "    cross-cache groom → kernel R/W → cred overwrite.\n");
    return IAMROOT_PRECOND_FAIL;
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
