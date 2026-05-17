/*
 * overlayfs_cve_2021_3493 — IAMROOT module
 *
 * Ubuntu-flavor overlayfs lets an unprivileged user mount overlayfs
 * inside a user namespace, then set file capabilities on a file in
 * the upper layer. The capabilities are NOT scoped to the userns —
 * they propagate to the host view of the same inode, letting an
 * unprivileged user create a file with CAP_SETUID/CAP_DAC_OVERRIDE
 * that root will honor outside the namespace.
 *
 * Discovered by Vasily Kulikov; published April 2021. Specific to
 * Ubuntu's modified overlayfs (vanilla upstream overlayfs didn't
 * allow the userns-mount path at the time). The fix landed via
 * Ubuntu's apparmor + an upstream Vfsmount audit.
 *
 * STATUS: 🔵 DETECT-ONLY. Exploit is well-documented (vsh's
 * exploit-cve-2021-3493) and would port in ~80 lines; follow-up
 * commit lands it.
 *
 * Affected:
 *   - Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 20.10 / 21.04 with
 *     Ubuntu-modified overlayfs and unprivileged_userns_clone=1.
 *   - Upstream kernels did NOT have the userns-mount path enabled
 *     pre-5.11, so non-Ubuntu kernels were largely immune by
 *     accident.
 *   - Fixed in Ubuntu by USN-4915-1 (April 2021) — kernel package
 *     updates per release.
 *
 * Detect logic (necessary-but-not-sufficient):
 *   1. /etc/os-release distro == ubuntu (the bug is Ubuntu-specific)
 *   2. Kernel version is below the Ubuntu fix threshold for that
 *      release. We don't track per-release Ubuntu kernel version
 *      maps in IAMROOT yet; report VULNERABLE if Ubuntu kernel
 *      AND uname() version < 5.11 AND unprivileged_userns_clone=1
 *      AND overlayfs mountable from userns (active probe).
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

static bool is_ubuntu(void)
{
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return false;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "ID=ubuntu") || strstr(line, "ID_LIKE=ubuntu")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static int read_sysctl_int(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    return atoi(buf);
}

/* Active probe: actually try to mount overlayfs inside a user
 * namespace. The probe is contained: forks a child that enters a
 * userns and attempts the mount; child exits regardless. Parent
 * never enters the namespace.
 *
 * Returns 1 if mount succeeded (vulnerable behavior), 0 if denied
 * (AppArmor / SELinux / kernel patch), -1 on probe machinery error. */
static int overlayfs_mount_probe(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) _exit(2);

        /* Build a minimal overlayfs in /tmp inside the child. */
        char base[] = "/tmp/iamroot-ovl-XXXXXX";
        if (!mkdtemp(base)) _exit(3);

        char low[512], up[512], wd[512], mp[512];
        snprintf(low, sizeof low, "%s/lower", base);
        snprintf(up,  sizeof up,  "%s/upper", base);
        snprintf(wd,  sizeof wd,  "%s/work",  base);
        snprintf(mp,  sizeof mp,  "%s/merged", base);
        if (mkdir(low, 0755) < 0 || mkdir(up, 0755) < 0
            || mkdir(wd, 0755) < 0 || mkdir(mp, 0755) < 0) _exit(4);

        char opts[2048];
        snprintf(opts, sizeof opts, "lowerdir=%s,upperdir=%s,workdir=%s",
                 low, up, wd);
        int rc = mount("overlay", mp, "overlay", 0, opts);
        if (rc < 0) _exit(5);   /* mount denied — likely patched/blocked */
        umount(mp);             /* clean up if we got here */
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status) == 0 ? 1 : 0;
}

static iamroot_result_t overlayfs_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] overlayfs: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Ubuntu-specific bug. Non-Ubuntu kernels are largely immune
     * because upstream didn't enable the userns-mount path until
     * 5.11. Bail early for non-Ubuntu. */
    if (!is_ubuntu()) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs: not Ubuntu — bug is Ubuntu-specific\n");
        }
        return IAMROOT_OK;
    }

    /* unprivileged_userns_clone gate */
    int uuc = read_sysctl_int("/proc/sys/kernel/unprivileged_userns_clone");
    if (uuc == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs: unprivileged_userns_clone=0 → "
                            "unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[i] overlayfs: Ubuntu kernel %s, unprivileged_userns_clone=%d\n",
                v.release, uuc);
    }

    /* Active probe: try the mount. Most reliable detect since Ubuntu
     * kernel package versioning is opaque to us. */
    if (ctx->active_probe) {
        int probe = overlayfs_mount_probe();
        if (probe == 1) {
            if (!ctx->json) {
                fprintf(stderr, "[!] overlayfs: ACTIVE PROBE CONFIRMED — "
                                "userns overlayfs mount succeeded → VULNERABLE\n");
            }
            return IAMROOT_VULNERABLE;
        }
        if (probe == 0) {
            if (!ctx->json) {
                fprintf(stderr, "[+] overlayfs: active probe denied mount — "
                                "likely patched / AppArmor block\n");
            }
            return IAMROOT_OK;
        }
        if (!ctx->json) {
            fprintf(stderr, "[?] overlayfs: active probe machinery failed\n");
        }
    }

    /* Without active probe, fall back to version inference. Upstream
     * 5.11 enabled userns-mount for overlayfs; Ubuntu had it earlier.
     * Ubuntu fix is per-release-specific; conservatively report
     * VULNERABLE if version < 5.13 (covers most affected Ubuntu LTS),
     * and recommend --active for confirmation. */
    if (v.major < 5 || (v.major == 5 && v.minor < 13)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] overlayfs: Ubuntu kernel %s in vulnerable range — "
                            "re-run with --active to confirm\n", v.release);
        }
        return IAMROOT_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] overlayfs: Ubuntu kernel %s is newer than typical "
                        "affected range\n", v.release);
        fprintf(stderr, "[i] overlayfs: re-run with --active to empirically test\n");
    }
    return IAMROOT_OK;
}

static iamroot_result_t overlayfs_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] overlayfs: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY (see CVES.md).\n"
        "    Reference: vsh's exploit-cve-2021-3493. The exploit mounts\n"
        "    overlayfs inside a userns, places a /bin/sh-like binary in\n"
        "    the upper layer with cap_setuid+ep set, then re-executes it\n"
        "    outside the namespace to drop a root shell.\n");
    return IAMROOT_PRECOND_FAIL;
}

/* ----- Embedded detection rules ----- */

static const char overlayfs_auditd[] =
    "# overlayfs userns LPE (CVE-2021-3493) — auditd detection rules\n"
    "# Flag userns-clone followed by overlayfs mount + setcap-like xattr.\n"
    "-a always,exit -F arch=b64 -S mount -F a2=overlay -k iamroot-overlayfs\n"
    "-a always,exit -F arch=b32 -S mount -F a2=overlay -k iamroot-overlayfs\n"
    "# Watch for security.capability xattr writes (the post-mount step)\n"
    "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr -k iamroot-overlayfs-cap\n";

const struct iamroot_module overlayfs_module = {
    .name           = "overlayfs",
    .cve            = "CVE-2021-3493",
    .summary        = "Ubuntu userns-overlayfs file-capability injection → host root",
    .family         = "overlayfs",
    .kernel_range   = "Ubuntu-specific; kernels w/ userns-overlayfs-mount before per-release fix (USN-4915-1)",
    .detect         = overlayfs_detect,
    .exploit        = overlayfs_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = overlayfs_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_overlayfs(void)
{
    iamroot_register(&overlayfs_module);
}
