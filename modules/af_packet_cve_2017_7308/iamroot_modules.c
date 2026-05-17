/*
 * af_packet_cve_2017_7308 — IAMROOT module
 *
 * AF_PACKET TPACKET_V3 ring-buffer setup integer-overflow → heap
 * write-where primitive. Discovered by Andrey Konovalov (March 2017).
 *
 * STATUS: 🔵 DETECT-ONLY. Konovalov's public PoC works end-to-end
 * — porting is a follow-up commit.
 *
 * Affected: kernel < 4.10.6 mainline. Stable backports:
 *   4.10.x : K >= 4.10.6
 *   4.9.x  : K >= 4.9.18  (LTS — RHEL 7-ish era)
 *   4.4.x  : K >= 4.4.57
 *   3.18.x : K >= 3.18.49
 *
 * Exploitation preconditions:
 *   - CAP_NET_RAW (via unprivileged user_ns) to create AF_PACKET socket
 *   - CONFIG_PACKET=y (almost always — even container kernels)
 *
 * Why famous: was the canonical "userns + AF_PACKET → root" chain for
 * Konovalov's research era. Many other AF_PACKET bugs followed (e.g.
 * CVE-2020-14386) sharing the same userns-clone gate.
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

static const struct kernel_patched_from af_packet_patched_branches[] = {
    {3, 18,  49},
    {4,  4,  57},
    {4,  9,  18},
    {4, 10,   6},
    {4, 11,   0},   /* mainline */
};

static const struct kernel_range af_packet_range = {
    .patched_from = af_packet_patched_branches,
    .n_patched_from = sizeof(af_packet_patched_branches) /
                      sizeof(af_packet_patched_branches[0]),
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

static iamroot_result_t af_packet_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] af_packet: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    bool patched = kernel_range_is_patched(&af_packet_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns();
    if (!ctx->json) {
        fprintf(stderr, "[i] af_packet: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] af_packet: user_ns+net_ns clone (CAP_NET_RAW gate): %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] af_packet: user_ns denied → "
                            "unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] af_packet: VULNERABLE — kernel in range AND user_ns reachable\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t af_packet_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] af_packet: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: Konovalov's PoC.\n"
        "    Exploit shape: unshare userns → setsockopt(SOL_PACKET,\n"
        "    PACKET_VERSION, TPACKET_V3) → setsockopt with crafted\n"
        "    tpacket_req3 (tp_block_size + tp_frame_size triggers overflow)\n"
        "    → heap write-where → cred overwrite.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char af_packet_auditd[] =
    "# AF_PACKET TPACKET_V3 LPE (CVE-2017-7308) — auditd detection rules\n"
    "# Flag AF_PACKET socket creation from non-root via userns.\n"
    "-a always,exit -F arch=b64 -S socket -F a0=17 -k iamroot-af-packet\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-af-packet-userns\n";

const struct iamroot_module af_packet_module = {
    .name           = "af_packet",
    .cve            = "CVE-2017-7308",
    .summary        = "AF_PACKET TPACKET_V3 integer overflow → heap write-where → cred overwrite",
    .family         = "af_packet",
    .kernel_range   = "K < 4.10.6, backports: 4.10.6 / 4.9.18 / 4.4.57 / 3.18.49",
    .detect         = af_packet_detect,
    .exploit        = af_packet_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = af_packet_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_af_packet(void)
{
    iamroot_register(&af_packet_module);
}
