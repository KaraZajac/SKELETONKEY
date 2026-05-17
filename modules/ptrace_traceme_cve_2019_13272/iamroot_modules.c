/*
 * ptrace_traceme_cve_2019_13272 — IAMROOT module
 *
 * PTRACE_TRACEME on a parent that subsequently execve's a setuid
 * binary results in the kernel granting ptrace privileges over the
 * privileged process to the unprivileged child. Discovered by Jann
 * Horn (Google Project Zero, June 2019).
 *
 * STATUS: 🔵 DETECT-ONLY. Exploit follows jannh's public PoC: fork
 * a child that does PTRACE_TRACEME pointing at the parent, parent
 * execve's a chosen setuid binary (e.g., su, pkexec), child then
 * ptrace-injects shellcode into the now-elevated process.
 *
 * Affected: kernels < 5.1.17 mainline. Stable backports varied; the
 * fix landed in stable as:
 *   5.1.x : K >= 5.1.17
 *   5.0.x : K >= 5.0.20 (older LTS — many distros stayed on 4.x)
 *   4.19.x: K >= 4.19.58
 *   4.14.x: K >= 4.14.131
 *   4.9.x : K >= 4.9.182
 *   4.4.x : K >= 4.4.182
 *
 * No exotic preconditions. Doesn't need user_ns. Works on
 * default-config systems — that's part of why it's famous: even
 * locked-down environments without unprivileged_userns_clone were
 * vulnerable.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct kernel_patched_from ptrace_traceme_patched_branches[] = {
    {4,  4, 182},
    {4,  9, 182},
    {4, 14, 131},
    {4, 19,  58},
    {5,  0,  20},
    {5,  1,  17},
    {5,  2,   0},   /* mainline (5.2-rc) */
};

static const struct kernel_range ptrace_traceme_range = {
    .patched_from = ptrace_traceme_patched_branches,
    .n_patched_from = sizeof(ptrace_traceme_patched_branches) /
                      sizeof(ptrace_traceme_patched_branches[0]),
};

static iamroot_result_t ptrace_traceme_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] ptrace_traceme: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug existed since ptrace's inception (early 2.x); anything
     * pre-LTS-backport is vulnerable. Anything < 4.4 in our range
     * model defaults to vulnerable since no entry covers it. */
    if (v.major < 4 || (v.major == 4 && v.minor < 4)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] ptrace_traceme: ancient kernel %s — assume VULNERABLE\n",
                    v.release);
        }
        return IAMROOT_VULNERABLE;
    }

    bool patched = kernel_range_is_patched(&ptrace_traceme_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] ptrace_traceme: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] ptrace_traceme: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] ptrace_traceme: no exotic preconditions — works on default config "
                        "(no user_ns required)\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t ptrace_traceme_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] ptrace_traceme: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: jannh's PoC.\n"
        "    Exploit shape: fork() → child calls PTRACE_TRACEME → parent\n"
        "    execve's a setuid binary (su, pkexec, ping with cap_net_raw,\n"
        "    etc.) → child becomes tracer of the now-privileged process\n"
        "    → ptrace-inject shellcode → root.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char ptrace_traceme_auditd[] =
    "# PTRACE_TRACEME LPE (CVE-2019-13272) — auditd detection rules\n"
    "# Flag PTRACE_TRACEME (request 0) followed by parent execve of\n"
    "# a setuid binary. False positives: gdb, strace, debuggers.\n"
    "-a always,exit -F arch=b64 -S ptrace -F a0=0 -k iamroot-ptrace-traceme\n"
    "-a always,exit -F arch=b32 -S ptrace -F a0=0 -k iamroot-ptrace-traceme\n";

const struct iamroot_module ptrace_traceme_module = {
    .name           = "ptrace_traceme",
    .cve            = "CVE-2019-13272",
    .summary        = "PTRACE_TRACEME → setuid binary execve → cred-escalation via ptrace inject",
    .family         = "ptrace_traceme",
    .kernel_range   = "K < 5.1.17, backports: 5.0.20 / 4.19.58 / 4.14.131 / 4.9.182 / 4.4.182",
    .detect         = ptrace_traceme_detect,
    .exploit        = ptrace_traceme_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR set ptrace_scope sysctl */
    .cleanup        = NULL,
    .detect_auditd  = ptrace_traceme_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_ptrace_traceme(void)
{
    iamroot_register(&ptrace_traceme_module);
}
