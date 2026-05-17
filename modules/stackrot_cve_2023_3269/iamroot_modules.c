/*
 * stackrot_cve_2023_3269 — IAMROOT module
 *
 * "Stack Rot": UAF in maple-tree-based VMA splitting. The maple
 * tree replaced the rbtree-based VMA store in 6.1; during split,
 * the kernel could write to a maple node after it was freed via
 * RCU. Exploitable for kernel R/W → cred overwrite.
 *
 * Discovered by Ruihan Li (Peking University), Jul 2023. Famous
 * because it was the first significant exploit landed against the
 * (then-recently-merged) maple tree code, and because the original
 * disclosure included a public PoC that worked on default-config
 * Ubuntu 23.04.
 *
 * STATUS: 🔵 DETECT-ONLY. Public PoC is ~1000 lines (heavy maple
 * tree state management + RCU-grace-period timing); a clean port
 * into iamroot_module form is a substantial follow-up.
 *
 * Affected: kernel 6.1.x — 6.4-rc4 mainline. Stable backports:
 *   6.3.x  : K >= 6.3.10
 *   6.1.x  : K >= 6.1.37 (LTS — most relevant)
 *   mainline 6.4-rc4+
 *
 * Pre-6.1 kernels are immune (no maple tree). 6.5+ are patched.
 *
 * Preconditions:
 *   - Unprivileged user_ns (to gain CAP_SYS_ADMIN inside userns for
 *     some triggers — actually the bug can be triggered without
 *     userns via plain mprotect/munmap split operations)
 *   - Default kernel config (CONFIG_USERFAULTFD recommended for
 *     deterministic exploitation, but not strictly required)
 *
 * Coverage rationale: 2023 mm-class bug. Different family than our
 * netfilter-heavy 2022-2024 modules — broadens the corpus shape.
 * Affects the 6.1 LTS kernels still widely deployed.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct kernel_patched_from stackrot_patched_branches[] = {
    {6, 1, 37},
    {6, 3, 10},
    {6, 4,  0},   /* mainline */
};

static const struct kernel_range stackrot_range = {
    .patched_from = stackrot_patched_branches,
    .n_patched_from = sizeof(stackrot_patched_branches) /
                      sizeof(stackrot_patched_branches[0]),
};

static iamroot_result_t stackrot_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] stackrot: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 6.1 (when maple tree landed). Pre-6.1 kernels
     * use rbtree-based VMAs and don't have this bug. */
    if (v.major < 6 || (v.major == 6 && v.minor < 1)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] stackrot: kernel %s predates maple-tree VMA code (introduced in 6.1)\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&stackrot_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] stackrot: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] stackrot: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] stackrot: mm-class bug — affects default-config kernels; "
                        "no exotic preconditions\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t stackrot_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] stackrot: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: Ruihan Li's public PoC\n"
        "    (~1000 lines maple-tree state + RCU grace period timing).\n"
        "    Exploit shape: mmap many VMAs → split via mprotect to trigger\n"
        "    maple node use-after-RCU → cross-cache groom → kernel R/W\n"
        "    → cred overwrite.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char stackrot_auditd[] =
    "# StackRot (CVE-2023-3269) — auditd detection rules\n"
    "# Hard to detect via syscall hooks alone — the trigger is mprotect/\n"
    "# munmap with specific VMA-split patterns. Flag unusual high-volume\n"
    "# mprotect bursts from non-root processes.\n"
    "-a always,exit -F arch=b64 -S mprotect -F success=1 -k iamroot-stackrot\n";

const struct iamroot_module stackrot_module = {
    .name           = "stackrot",
    .cve            = "CVE-2023-3269",
    .summary        = "maple-tree VMA-split UAF (StackRot) → kernel R/W → cred overwrite",
    .family         = "stackrot",
    .kernel_range   = "6.1 ≤ K < 6.4-rc4, backports: 6.3.10 / 6.1.37 (LTS)",
    .detect         = stackrot_detect,
    .exploit        = stackrot_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = stackrot_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_stackrot(void)
{
    iamroot_register(&stackrot_module);
}
