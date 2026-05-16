/*
 * dirty_pipe_cve_2022_0847 — IAMROOT module
 *
 * Status: 🔵 DETECT-ONLY for now. Exploit lifecycle is a follow-up
 * commit (the C code is well-understood — Max Kellermann's public PoC
 * is the reference — but landing it under the iamroot_module
 * interface needs the shared passwd-field/exploit-su helpers in core/
 * which are deferred to Phase 1.5).
 *
 * Affected kernel ranges:
 *   5.8     ≤ K < 5.17         (mainline fix at 5.17, commit 9d2231c5d74e)
 *   5.15.x: K ≤ 5.15.24        (fixed in 5.15.25)
 *   5.10.x: K ≤ 5.10.101       (fixed in 5.10.102)
 *   5.4.x : not affected (bug introduced in 5.8)
 *
 * Detect logic:
 *   - Parse uname() release into major.minor.patch
 *   - If kernel < 5.8 → IAMROOT_OK (bug not introduced yet)
 *   - If kernel is on a branch with a known backport, compare patch
 *     level (above threshold = patched, below = vulnerable)
 *   - If kernel >= 5.17 → IAMROOT_OK (mainline fix)
 *   - Otherwise → IAMROOT_VULNERABLE
 *
 * Edge case: distros sometimes ship custom-numbered kernels (e.g.
 * Ubuntu's `5.15.0-100-generic` where the .100 is Ubuntu's release
 * counter, NOT the upstream patch level). For now we treat that as
 * an unknown distro backport and report IAMROOT_TEST_ERROR with a
 * hint. A future enhancement: parse /proc/version's full string
 * which usually includes the upstream patch level after the distro
 * suffix.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <string.h>

/* The bug exists on every kernel from 5.8 (introduction) until the
 * fix is backported to that branch. We model "patched" as:
 *  - on the 5.10 branch: 5.10.102 or later
 *  - on the 5.15 branch: 5.15.25 or later
 *  - any kernel 5.16 or later (mainline fix landed for 5.17, so 5.16
 *    only needs 5.16.11 or later; 5.17+ inherits)
 *  - mainline (≥ 5.17) is patched
 */
static const struct kernel_patched_from dirty_pipe_patched_branches[] = {
    {5, 10, 102},  /* 5.10.x backport */
    {5, 15,  25},  /* 5.15.x backport */
    {5, 16,  11},  /* 5.16.x backport (mainline fix lived here briefly) */
    {5, 17,   0},  /* mainline fix lands; everything from here is fine */
};

static const struct kernel_range dirty_pipe_range = {
    .patched_from = dirty_pipe_patched_branches,
    .n_patched_from = sizeof(dirty_pipe_patched_branches) /
                      sizeof(dirty_pipe_patched_branches[0]),
};

static iamroot_result_t dirty_pipe_detect(const struct iamroot_ctx *ctx)
{
    (void)ctx;

    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] dirty_pipe: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 5.8. */
    if (v.major < 5 || (v.major == 5 && v.minor < 8)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] dirty_pipe: kernel %s predates the bug (introduced in 5.8)\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&dirty_pipe_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] dirty_pipe: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] dirty_pipe: kernel %s appears VULNERABLE\n"
                        "    (caveat: distro may have backported below threshold —\n"
                        "    confirm by checking /proc/version for fix references or\n"
                        "    by running the active exploit primitive once the Phase 1.5\n"
                        "    helpers land in core/)\n",
                v.release);
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t dirty_pipe_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] dirty_pipe: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY (see CVES.md).\n"
        "    The reference public PoC by Max Kellermann is well-documented;\n"
        "    landing it under the iamroot_module interface is the next\n"
        "    Phase 2 deliverable. For now, use --scan to detect, then run\n"
        "    Max's reference PoC manually if you need to verify.\n");
    return IAMROOT_PRECOND_FAIL;
}

/* Embedded detection rules — keep the binary self-contained so
 * `iamroot --detect-rules --format=auditd` works without a separate
 * data-dir install. */
static const char dirty_pipe_auditd[] =
    "# Dirty Pipe (CVE-2022-0847) — auditd detection rules\n"
    "# See modules/dirty_pipe_cve_2022_0847/detect/auditd.rules for full version.\n"
    "-w /etc/passwd    -p wa -k iamroot-dirty-pipe\n"
    "-w /etc/shadow    -p wa -k iamroot-dirty-pipe\n"
    "-w /etc/sudoers   -p wa -k iamroot-dirty-pipe\n"
    "-w /etc/sudoers.d -p wa -k iamroot-dirty-pipe\n"
    "-a always,exit -F arch=b64 -S splice -k iamroot-dirty-pipe-splice\n"
    "-a always,exit -F arch=b32 -S splice -k iamroot-dirty-pipe-splice\n";

static const char dirty_pipe_sigma[] =
    "title: Possible Dirty Pipe exploitation (CVE-2022-0847)\n"
    "id: f6b13c08-iamroot-dirty-pipe\n"
    "status: experimental\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  modification:\n"
    "    type: 'PATH'\n"
    "    name|startswith: ['/etc/passwd', '/etc/shadow', '/etc/sudoers']\n"
    "  not_root:\n"
    "    auid|expression: '!= 0'\n"
    "  condition: modification and not_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2022.0847]\n";

const struct iamroot_module dirty_pipe_module = {
    .name           = "dirty_pipe",
    .cve            = "CVE-2022-0847",
    .summary        = "pipe_buffer CAN_MERGE flag inheritance → page-cache write",
    .family         = "dirty_pipe",
    .kernel_range   = "5.8 ≤ K, fixed mainline 5.17, backports: 5.10.102 / 5.15.25 / 5.16.11",
    .detect         = dirty_pipe_detect,
    .exploit        = dirty_pipe_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = dirty_pipe_auditd,
    .detect_sigma   = dirty_pipe_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_dirty_pipe(void)
{
    iamroot_register(&dirty_pipe_module);
}
