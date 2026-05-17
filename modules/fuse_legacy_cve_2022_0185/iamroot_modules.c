/*
 * fuse_legacy_cve_2022_0185 — IAMROOT module
 *
 * legacy_parse_param() in fs/fs_context.c had a heap overflow when
 * parsing the "fsconfig" filesystem option strings — specifically,
 * legacy_load_simple_buf() didn't bound-check the option length.
 * Originally reported as a FUSE mount path bug but actually applies
 * to any filesystem mountable from a userns (FUSE was just the
 * easiest reach).
 *
 * Discovered by William Liu / Crusaders of Rust (Jan 2022). Famous
 * in container-escape contexts (docker/k8s, especially rootless).
 *
 * STATUS: 🔵 DETECT-ONLY. Public PoC by William Liu (gh repo
 * Crusaders-of-Rust/CVE-2022-0185) demonstrates kernel R/W + cred
 * overwrite via cross-cache UAF; porting is a follow-up.
 *
 * Affected: kernel 5.1+ until fix:
 *   Mainline fix: 722d94847de29 (Jan 18 2022) — lands in 5.16.2
 *   5.16.x : K >= 5.16.2
 *   5.15.x : K >= 5.15.14
 *   5.10.x : K >= 5.10.91
 *   5.4.x  : K >= 5.4.171
 *
 * Preconditions:
 *   - Unprivileged user_ns + mount-ns (to get CAP_SYS_ADMIN inside userns)
 *   - Any mountable filesystem from userns context (legacy_load path
 *     used FUSE, but cgroup2 and others also reach the bug)
 *
 * For "tool for system admins": this is the container-escape angle.
 * Workloads running rootless containers (Podman, snap, flatpak) sit
 * on this bug if the host kernel is unpatched and unprivileged_userns
 * is enabled.
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

static const struct kernel_patched_from fuse_legacy_patched_branches[] = {
    {5,  4, 171},
    {5, 10,  91},
    {5, 15,  14},
    {5, 16,   2},
    {5, 17,   0},   /* mainline */
};

static const struct kernel_range fuse_legacy_range = {
    .patched_from = fuse_legacy_patched_branches,
    .n_patched_from = sizeof(fuse_legacy_patched_branches) /
                      sizeof(fuse_legacy_patched_branches[0]),
};

static int can_unshare_userns_mount(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static iamroot_result_t fuse_legacy_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] fuse_legacy: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 5.1 (when legacy_parse_param landed). Pre-5.1
     * kernels predate the code path entirely. */
    if (v.major < 5 || (v.major == 5 && v.minor < 1)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: kernel %s predates the bug introduction\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&fuse_legacy_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns_mount();
    if (!ctx->json) {
        fprintf(stderr, "[i] fuse_legacy: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] fuse_legacy: user_ns+mount_ns clone (CAP_SYS_ADMIN gate): %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: user_ns denied → "
                            "unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] fuse_legacy: VULNERABLE — kernel in range AND "
                        "userns+mountns reachable\n");
        fprintf(stderr, "[i] fuse_legacy: container-escape relevant for rootless "
                        "docker/podman/snap setups\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t fuse_legacy_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] fuse_legacy: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: William Liu's PoC\n"
        "    (github.com/Crusaders-of-Rust/CVE-2022-0185). Exploit\n"
        "    shape: unshare userns+mountns → fsopen('cgroup2') →\n"
        "    fsconfig with crafted long option string → heap OOB write\n"
        "    → msg_msg cross-cache groom → kernel R/W → cred overwrite.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char fuse_legacy_auditd[] =
    "# CVE-2022-0185 — auditd detection rules\n"
    "# Flag unshare(USER|NS) chained with fsopen/fsconfig from non-root.\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-fuse-legacy\n"
    "-a always,exit -F arch=b64 -S fsopen -k iamroot-fuse-legacy-fsopen\n"
    "-a always,exit -F arch=b64 -S fsconfig -k iamroot-fuse-legacy-fsconfig\n";

const struct iamroot_module fuse_legacy_module = {
    .name           = "fuse_legacy",
    .cve            = "CVE-2022-0185",
    .summary        = "legacy_parse_param fsconfig heap OOB → container-escape LPE",
    .family         = "fuse_legacy",
    .kernel_range   = "5.1 ≤ K, fixed mainline 5.16.2; backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171",
    .detect         = fuse_legacy_detect,
    .exploit        = fuse_legacy_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = fuse_legacy_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_fuse_legacy(void)
{
    iamroot_register(&fuse_legacy_module);
}
