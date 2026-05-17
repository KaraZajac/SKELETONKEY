/*
 * IAMROOT — top-level dispatcher
 *
 * Usage:
 *   iamroot --scan                    # run every module's detect()
 *   iamroot --scan --json             # machine-readable output
 *   iamroot --scan --active           # invasive probes (still no /etc/passwd writes)
 *   iamroot --list                    # list registered modules
 *   iamroot --exploit <name> --i-know # run a named module's exploit
 *   iamroot --mitigate <name>         # apply a temporary mitigation
 *   iamroot --cleanup <name>          # undo --exploit or --mitigate side effects
 *
 * Phase 1 scope: thin dispatcher over the copy_fail_family bridge.
 * Future phases add: --detect-rules export, multi-family registry,
 * fingerprint pre-pass, etc.
 */

#include "core/module.h"
#include "core/registry.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IAMROOT_VERSION "0.1.0"

static const char BANNER[] =
"\n"
" ██╗ █████╗ ███╗   ███╗██████╗  ██████╗  ██████╗ ████████╗\n"
" ██║██╔══██╗████╗ ████║██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝\n"
" ██║███████║██╔████╔██║██████╔╝██║   ██║██║   ██║   ██║   \n"
" ██║██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║██║   ██║   ██║   \n"
" ██║██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝╚██████╔╝   ██║   \n"
" ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   \n"
"   Curated Linux kernel LPE corpus — v" IAMROOT_VERSION "\n"
"   AUTHORIZED TESTING ONLY — see docs/ETHICS.md\n";

static void usage(const char *prog)
{
    fprintf(stderr,
"Usage: %s [MODE] [OPTIONS]\n"
"\n"
"Modes (default: --scan):\n"
"  --scan                run every module's detect() across the host\n"
"  --list                list registered modules and exit\n"
"  --exploit <name>      run named module's exploit (REQUIRES --i-know)\n"
"  --mitigate <name>     apply named module's mitigation\n"
"  --cleanup <name>      undo named module's exploit/mitigate side effects\n"
"  --detect-rules        dump detection rules for every module\n"
"                        (combine with --format=auditd|sigma|yara|falco)\n"
"  --module-info <name>  full metadata + rule bodies for one module\n"
"                        (combine with --json for machine-readable output)\n"
"  --audit               system-hygiene scan: setuid binaries, world-writable\n"
"                        files in /etc, file capabilities, sudo NOPASSWD\n"
"                        (complements --scan; answers 'is this box\n"
"                        generally privesc-exposed?')\n"
"  --version             print version\n"
"  --help                this message\n"
"\n"
"Options:\n"
"  --i-know              authorization gate for --exploit modes\n"
"  --active              in --scan, do invasive sentinel probes (no /etc/passwd writes)\n"
"  --no-shell            in --exploit modes, prepare but don't drop to shell\n"
"  --full-chain          in --exploit modes, attempt full root-pop after primitive\n"
"                        (the 🟡 modules return primitive-only by default; with\n"
"                        --full-chain they continue to leak → arb-write →\n"
"                        modprobe_path overwrite. Requires resolvable kernel\n"
"                        offsets — env vars, /proc/kallsyms, or /boot/System.map.\n"
"                        See docs/OFFSETS.md.)\n"
"  --json                machine-readable output (for SIEM/CI)\n"
"  --no-color            disable ANSI color codes\n"
"  --format <f>          with --detect-rules: auditd (default), sigma, yara, falco\n"
"\n"
"Exit codes:\n"
"  0 not vulnerable / OK    2 vulnerable   5 exploit succeeded\n"
"  1 test error             3 exploit failed   4 preconditions missing\n",
        prog);
}

enum mode {
    MODE_SCAN,
    MODE_LIST,
    MODE_EXPLOIT,
    MODE_MITIGATE,
    MODE_CLEANUP,
    MODE_DETECT_RULES,
    MODE_MODULE_INFO,
    MODE_AUDIT,
    MODE_HELP,
    MODE_VERSION,
};

enum detect_format {
    FMT_AUDITD,
    FMT_SIGMA,
    FMT_YARA,
    FMT_FALCO,
};

static const char *result_str(iamroot_result_t r)
{
    switch (r) {
    case IAMROOT_OK:            return "OK";
    case IAMROOT_TEST_ERROR:    return "ERROR";
    case IAMROOT_VULNERABLE:    return "VULNERABLE";
    case IAMROOT_EXPLOIT_FAIL:  return "EXPLOIT_FAIL";
    case IAMROOT_PRECOND_FAIL:  return "PRECOND_FAIL";
    case IAMROOT_EXPLOIT_OK:    return "EXPLOIT_OK";
    }
    return "?";
}

/* JSON-escape a string for inclusion in stdout output. Quick + safe:
 * escapes \" and \\ and newlines; passes through ASCII printable.
 * Caller must call json_escape_done() to free the result. */
static char *json_escape(const char *s)
{
    if (s == NULL) return NULL;
    size_t n = strlen(s);
    char *out = malloc(n * 2 + 1);   /* worst case: every char doubles */
    if (!out) return NULL;
    char *p = out;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { *p++ = '\\'; *p++ = c; }
        else if (c == '\n') { *p++ = '\\'; *p++ = 'n'; }
        else if (c == '\r') { *p++ = '\\'; *p++ = 'r'; }
        else if (c == '\t') { *p++ = '\\'; *p++ = 't'; }
        else if (c < 0x20) { /* skip — should be rare in our strings */ }
        else *p++ = c;
    }
    *p = 0;
    return out;
}

static void emit_module_json(const struct iamroot_module *m, bool include_rules)
{
    char *name    = json_escape(m->name);
    char *cve     = json_escape(m->cve);
    char *summary = json_escape(m->summary);
    char *family  = json_escape(m->family);
    char *krange  = json_escape(m->kernel_range);
    fprintf(stdout,
        "{\"name\":\"%s\",\"cve\":\"%s\",\"family\":\"%s\","
        "\"kernel_range\":\"%s\",\"summary\":\"%s\","
        "\"has\":{\"detect\":%s,\"exploit\":%s,\"mitigate\":%s,\"cleanup\":%s,"
        "\"auditd\":%s,\"sigma\":%s,\"yara\":%s,\"falco\":%s}",
        name ? name : "",
        cve ? cve : "",
        family ? family : "",
        krange ? krange : "",
        summary ? summary : "",
        m->detect        ? "true" : "false",
        m->exploit       ? "true" : "false",
        m->mitigate      ? "true" : "false",
        m->cleanup       ? "true" : "false",
        m->detect_auditd ? "true" : "false",
        m->detect_sigma  ? "true" : "false",
        m->detect_yara   ? "true" : "false",
        m->detect_falco  ? "true" : "false");
    if (include_rules) {
        /* Embed the actual rule text. Useful for --module-info. */
        char *aud = json_escape(m->detect_auditd);
        char *sig = json_escape(m->detect_sigma);
        char *yar = json_escape(m->detect_yara);
        char *fal = json_escape(m->detect_falco);
        fprintf(stdout,
            ",\"detect_rules\":{\"auditd\":%s%s%s,\"sigma\":%s%s%s,"
            "\"yara\":%s%s%s,\"falco\":%s%s%s}",
            aud ? "\"" : "", aud ? aud : "null", aud ? "\"" : "",
            sig ? "\"" : "", sig ? sig : "null", sig ? "\"" : "",
            yar ? "\"" : "", yar ? yar : "null", yar ? "\"" : "",
            fal ? "\"" : "", fal ? fal : "null", fal ? "\"" : "");
        free(aud); free(sig); free(yar); free(fal);
    }
    fprintf(stdout, "}");
    free(name); free(cve); free(summary); free(family); free(krange);
}

static int cmd_list(const struct iamroot_ctx *ctx)
{
    size_t n = iamroot_module_count();
    if (ctx->json) {
        fprintf(stdout, "{\"version\":\"%s\",\"modules\":[", IAMROOT_VERSION);
        for (size_t i = 0; i < n; i++) {
            if (i) fputc(',', stdout);
            emit_module_json(iamroot_module_at(i), false);
        }
        fprintf(stdout, "]}\n");
        return 0;
    }
    fprintf(stdout, "%-20s %-18s %-25s %s\n",
            "NAME", "CVE", "FAMILY", "SUMMARY");
    fprintf(stdout, "%-20s %-18s %-25s %s\n",
            "----", "---", "------", "-------");
    for (size_t i = 0; i < n; i++) {
        const struct iamroot_module *m = iamroot_module_at(i);
        fprintf(stdout, "%-20s %-18s %-25s %s\n",
                m->name, m->cve, m->family, m->summary);
    }
    return 0;
}

/* --audit: system-hygiene scan beyond per-CVE detect. Inventories
 * setuid binaries, world-writable system files, capability-bound
 * non-standard binaries, NOPASSWD sudo entries. Complements --scan;
 * answers "is this box generally exposed to privesc?" beyond
 * "does it have any of the known kernel CVEs?".
 *
 * Output is structured findings. --json switches to a single JSON
 * object with arrays per category. Side-effect-free: read-only
 * filesystem walks. */
struct finding {
    const char *category;   /* "setuid", "world_writable", "capability", "sudo" */
    char        path[512];
    char        note[256];
};

static void print_finding_human(const struct finding *f)
{
    fprintf(stdout, "[%-15s] %-50s  %s\n",
            f->category, f->path, f->note);
}

/* Walk one filesystem path looking for setuid-root binaries. Bounded
 * via find(1) for portability (every distro ships find). */
static int audit_setuid(int *count_out, bool json,
                        bool *first_json_emitted)
{
    /* Use popen() on `find` rather than recursive opendir() — much
     * simpler, every distro ships find. Limit to common
     * binary-bearing dirs to keep runtime reasonable. */
    static const char *cmd =
        "find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin "
        "-xdev -perm -4000 -type f 2>/dev/null";
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[1024];
    int n = 0;
    /* Set of suspicious binaries — these are notable in the LPE world.
     * The full setuid inventory is informational; this list flags
     * specific items as "review this". */
    static const struct { const char *path; const char *note; } SUSP[] = {
        {"/usr/bin/pkexec",  "Pwnkit CVE-2021-4034 history; tightly audit polkit policy"},
        {"/usr/bin/mount.cifs", "historically setuid-root; check distro hardening"},
        {"/usr/bin/fusermount3", "historically setuid; userns-related LPE history"},
        {"/usr/bin/passwd",  "expected setuid; verify integrity"},
        {"/usr/bin/sudo",    "expected setuid; verify integrity + sudoers"},
        {"/usr/bin/su",      "expected setuid; verify integrity"},
        {"/usr/lib/snapd/snap-confine", "Ubuntu snap sandbox-escape history"},
        {NULL, NULL},
    };
    while (fgets(line, sizeof line, p)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        const char *note = "setuid binary — review";
        for (size_t i = 0; SUSP[i].path; i++) {
            if (strcmp(line, SUSP[i].path) == 0) { note = SUSP[i].note; break; }
        }
        if (json) {
            char *p_esc = json_escape(line);
            char *n_esc = json_escape(note);
            fprintf(stdout, "%s{\"category\":\"setuid\",\"path\":\"%s\",\"note\":\"%s\"}",
                    *first_json_emitted ? "," : "",
                    p_esc ? p_esc : "", n_esc ? n_esc : "");
            *first_json_emitted = true;
            free(p_esc); free(n_esc);
        } else {
            struct finding f = { .category = "setuid" };
            snprintf(f.path, sizeof f.path, "%s", line);
            snprintf(f.note, sizeof f.note, "%s", note);
            print_finding_human(&f);
        }
        n++;
    }
    pclose(p);
    if (count_out) *count_out = n;
    return 0;
}

/* Look for world-writable files inside /etc. Catches obviously-broken
 * filesystem permissions where any user can edit system config. */
static int audit_world_writable(int *count_out, bool json,
                                bool *first_json_emitted)
{
    static const char *cmd =
        "find /etc -xdev -perm -0002 -type f 2>/dev/null";
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof line, p)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        const char *note = "world-writable in /etc — anyone can edit";
        if (json) {
            char *p_esc = json_escape(line);
            fprintf(stdout, "%s{\"category\":\"world_writable\",\"path\":\"%s\",\"note\":\"%s\"}",
                    *first_json_emitted ? "," : "", p_esc ? p_esc : "", note);
            *first_json_emitted = true;
            free(p_esc);
        } else {
            struct finding f = { .category = "world_writable" };
            snprintf(f.path, sizeof f.path, "%s", line);
            snprintf(f.note, sizeof f.note, "%s", note);
            print_finding_human(&f);
        }
        n++;
    }
    pclose(p);
    if (count_out) *count_out = n;
    return 0;
}

/* Find files with file capabilities set. cap_setuid+ep or
 * cap_dac_override+ep on a non-standard binary = potential
 * post-exploit persistence or a misconfigured capability grant. */
static int audit_capabilities(int *count_out, bool json,
                              bool *first_json_emitted)
{
    /* getcap is in libcap2-bin / libcap-progs depending on distro;
     * skip cleanly if absent. */
    if (access("/sbin/getcap", X_OK) != 0
        && access("/usr/sbin/getcap", X_OK) != 0
        && access("/usr/bin/getcap", X_OK) != 0) {
        if (!json) {
            fprintf(stderr, "[i] audit: getcap not installed — skipping capability scan\n");
        }
        if (count_out) *count_out = 0;
        return 0;
    }
    static const char *cmd =
        "getcap -r /usr/bin /usr/sbin /bin /sbin /usr/local 2>/dev/null";
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof line, p)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        const char *note = "file capability set — verify legitimacy";
        if (strstr(line, "cap_setuid+ep") || strstr(line, "cap_setgid+ep")
            || strstr(line, "cap_dac_override+ep") || strstr(line, "cap_sys_admin+ep")) {
            note = "high-power cap+ep — privesc-equivalent if attacker-writable";
        }
        if (json) {
            char *p_esc = json_escape(line);
            fprintf(stdout, "%s{\"category\":\"capability\",\"path\":\"%s\",\"note\":\"%s\"}",
                    *first_json_emitted ? "," : "", p_esc ? p_esc : "", note);
            *first_json_emitted = true;
            free(p_esc);
        } else {
            struct finding f = { .category = "capability" };
            snprintf(f.path, sizeof f.path, "%s", line);
            snprintf(f.note, sizeof f.note, "%s", note);
            print_finding_human(&f);
        }
        n++;
    }
    pclose(p);
    if (count_out) *count_out = n;
    return 0;
}

/* Check /etc/sudoers and /etc/sudoers.d for NOPASSWD entries. Many
 * setups have legit NOPASSWD for service accounts; flag and let
 * operator review. */
static int audit_sudo_nopasswd(int *count_out, bool json,
                               bool *first_json_emitted)
{
    static const char *cmd =
        "grep -rIn -E '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null";
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof line, p)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        const char *note = "sudo NOPASSWD entry — verify scope";
        if (json) {
            char *p_esc = json_escape(line);
            fprintf(stdout, "%s{\"category\":\"sudo\",\"path\":\"%s\",\"note\":\"%s\"}",
                    *first_json_emitted ? "," : "", p_esc ? p_esc : "", note);
            *first_json_emitted = true;
            free(p_esc);
        } else {
            struct finding f = { .category = "sudo" };
            snprintf(f.path, sizeof f.path, "%s", line);
            snprintf(f.note, sizeof f.note, "%s", note);
            print_finding_human(&f);
        }
        n++;
    }
    pclose(p);
    if (count_out) *count_out = n;
    return 0;
}

static int cmd_audit(const struct iamroot_ctx *ctx)
{
    int n_setuid = 0, n_ww = 0, n_cap = 0, n_sudo = 0;
    if (ctx->json) {
        fprintf(stdout, "{\"version\":\"%s\",\"audit\":[", IAMROOT_VERSION);
        bool first = false;
        audit_setuid(&n_setuid, true, &first);
        audit_world_writable(&n_ww, true, &first);
        audit_capabilities(&n_cap, true, &first);
        audit_sudo_nopasswd(&n_sudo, true, &first);
        fprintf(stdout, "],\"summary\":{\"setuid\":%d,\"world_writable\":%d,"
                        "\"capability\":%d,\"sudo_nopasswd\":%d}}\n",
                n_setuid, n_ww, n_cap, n_sudo);
    } else {
        fprintf(stdout, "%-17s %-50s  %s\n", "CATEGORY", "PATH", "NOTE");
        fprintf(stdout, "%-17s %-50s  %s\n", "--------", "----", "----");
        bool first = false;
        audit_setuid(&n_setuid, false, &first);
        audit_world_writable(&n_ww, false, &first);
        audit_capabilities(&n_cap, false, &first);
        audit_sudo_nopasswd(&n_sudo, false, &first);
        fprintf(stderr, "\n[*] audit summary: %d setuid, %d world-writable, "
                        "%d capability-set, %d sudo NOPASSWD\n",
                n_setuid, n_ww, n_cap, n_sudo);
    }
    return 0;
}

/* --module-info <name>: dump everything we know about one module.
 * Human-readable by default, JSON with --json. Includes the full
 * detection-rule text bodies for that module. */
static int cmd_module_info(const char *name, const struct iamroot_ctx *ctx)
{
    const struct iamroot_module *m = iamroot_module_find(name);
    if (!m) {
        if (ctx->json) {
            fprintf(stdout, "{\"error\":\"module not found\",\"name\":\"%s\"}\n", name);
        } else {
            fprintf(stderr, "[-] no module '%s'. Try --list.\n", name);
        }
        return 1;
    }
    if (ctx->json) {
        emit_module_json(m, true);
        fputc('\n', stdout);
        return 0;
    }
    fprintf(stdout, "name:          %s\n", m->name);
    fprintf(stdout, "cve:           %s\n", m->cve);
    fprintf(stdout, "family:        %s\n", m->family);
    fprintf(stdout, "kernel_range:  %s\n", m->kernel_range);
    fprintf(stdout, "summary:       %s\n", m->summary);
    fprintf(stdout, "operations:    %s%s%s%s\n",
        m->detect   ? "detect "   : "",
        m->exploit  ? "exploit "  : "",
        m->mitigate ? "mitigate " : "",
        m->cleanup  ? "cleanup "  : "");
    fprintf(stdout, "detect rules:  %s%s%s%s\n",
        m->detect_auditd ? "auditd " : "",
        m->detect_sigma  ? "sigma "  : "",
        m->detect_yara   ? "yara "   : "",
        m->detect_falco  ? "falco "  : "");
    if (m->detect_auditd) {
        fprintf(stdout, "\n--- auditd rules ---\n%s", m->detect_auditd);
    }
    if (m->detect_sigma) {
        fprintf(stdout, "\n--- sigma rule ---\n%s", m->detect_sigma);
    }
    return 0;
}

static int cmd_scan(const struct iamroot_ctx *ctx)
{
    int worst = 0;
    size_t n = iamroot_module_count();
    if (!ctx->json) {
        fprintf(stderr, "[*] iamroot scan: %zu module(s) registered\n", n);
    } else {
        fprintf(stdout, "{\"version\":\"%s\",\"modules\":[", IAMROOT_VERSION);
    }
    for (size_t i = 0; i < n; i++) {
        const struct iamroot_module *m = iamroot_module_at(i);
        if (m->detect == NULL) continue;
        iamroot_result_t r = m->detect(ctx);
        if (ctx->json) {
            fprintf(stdout, "%s{\"name\":\"%s\",\"cve\":\"%s\",\"result\":\"%s\"}",
                    (i == 0 ? "" : ","), m->name, m->cve, result_str(r));
        } else {
            fprintf(stdout, "[%s] %-20s  %-18s  %s\n",
                    result_str(r), m->name, m->cve, m->summary);
        }
        /* track worst (highest) result code as overall exit */
        if ((int)r > worst) worst = (int)r;
    }
    if (ctx->json) {
        fprintf(stdout, "]}\n");
    }
    return worst;
}

/* Dump detection rules for every registered module in the requested
 * format. Modules that don't ship a rule for that format are simply
 * skipped (no error). Output goes to stdout so it can be redirected
 * straight into /etc/audit/rules.d/, the SIEM, etc. */
static int cmd_detect_rules(enum detect_format fmt)
{
    static const char *fmt_names[] = {
        [FMT_AUDITD] = "auditd",
        [FMT_SIGMA]  = "sigma",
        [FMT_YARA]   = "yara",
        [FMT_FALCO]  = "falco",
    };
    size_t n = iamroot_module_count();
    fprintf(stdout, "# IAMROOT detection rules — format: %s\n", fmt_names[fmt]);
    fprintf(stdout, "# Generated from %zu registered modules\n", n);
    fprintf(stdout, "# AUTHORIZED-TESTING tool; see docs/ETHICS.md\n\n");
    /* Dedup by pointer: family-shared rule strings (e.g. all 5
     * copy_fail_family modules share one auditd rule string) would
     * otherwise emit identical blocks once per module. */
    const char *seen[64] = {0};
    size_t n_seen = 0;
    int emitted = 0;
    for (size_t i = 0; i < n; i++) {
        const struct iamroot_module *m = iamroot_module_at(i);
        const char *rules = NULL;
        switch (fmt) {
        case FMT_AUDITD: rules = m->detect_auditd; break;
        case FMT_SIGMA:  rules = m->detect_sigma;  break;
        case FMT_YARA:   rules = m->detect_yara;   break;
        case FMT_FALCO:  rules = m->detect_falco;  break;
        }
        if (rules == NULL) continue;
        /* Already emitted? */
        bool dup = false;
        for (size_t k = 0; k < n_seen; k++) {
            if (seen[k] == rules) { dup = true; break; }
        }
        if (dup) {
            fprintf(stdout, "# === %s (%s) — see family rules above ===\n\n",
                    m->name, m->cve);
            continue;
        }
        if (n_seen < sizeof(seen)/sizeof(seen[0])) seen[n_seen++] = rules;
        fprintf(stdout, "# === %s (%s) ===\n", m->name, m->cve);
        fputs(rules, stdout);
        fputc('\n', stdout);
        emitted++;
    }
    fprintf(stderr, "[*] emitted detection rules for %d / %zu module(s) (format: %s)\n",
            emitted, n, fmt_names[fmt]);
    return 0;
}

static int cmd_one(const struct iamroot_module *m, const char *op,
                   const struct iamroot_ctx *ctx)
{
    iamroot_result_t (*fn)(const struct iamroot_ctx *) = NULL;
    if (strcmp(op, "exploit") == 0)        fn = m->exploit;
    else if (strcmp(op, "mitigate") == 0)  fn = m->mitigate;
    else if (strcmp(op, "cleanup") == 0)   fn = m->cleanup;

    if (fn == NULL) {
        fprintf(stderr, "[-] module '%s' has no %s operation\n", m->name, op);
        return 1;
    }
    iamroot_result_t r = fn(ctx);
    fprintf(stderr, "[*] %s --%s result: %s\n", m->name, op, result_str(r));
    return (int)r;
}

int main(int argc, char **argv)
{
    /* Bring up the module registry. As new families land, add their
     * register_* call here. */
    iamroot_register_copy_fail_family();
    iamroot_register_dirty_pipe();
    iamroot_register_entrybleed();
    iamroot_register_pwnkit();
    iamroot_register_nf_tables();
    iamroot_register_overlayfs();
    iamroot_register_cls_route4();
    iamroot_register_dirty_cow();
    iamroot_register_ptrace_traceme();
    iamroot_register_netfilter_xtcompat();
    iamroot_register_af_packet();
    iamroot_register_fuse_legacy();
    iamroot_register_stackrot();
    iamroot_register_af_packet2();
    iamroot_register_cgroup_release_agent();
    iamroot_register_overlayfs_setuid();

    enum mode mode = MODE_SCAN;
    struct iamroot_ctx ctx = {0};
    const char *target = NULL;
    int i_know = 0;

    enum detect_format dr_fmt = FMT_AUDITD;
    static struct option longopts[] = {
        {"scan",          no_argument,       0, 'S'},
        {"list",          no_argument,       0, 'L'},
        {"exploit",       required_argument, 0, 'E'},
        {"mitigate",      required_argument, 0, 'M'},
        {"cleanup",       required_argument, 0, 'C'},
        {"detect-rules",  no_argument,       0, 'D'},
        {"module-info",   required_argument, 0, 'I'},
        {"audit",         no_argument,       0, 'A'},
        {"format",        required_argument, 0,  6 },
        {"i-know",        no_argument,       0,  1 },
        {"active",        no_argument,       0,  2 },
        {"no-shell",      no_argument,       0,  3 },
        {"json",          no_argument,       0,  4 },
        {"no-color",      no_argument,       0,  5 },
        {"full-chain",    no_argument,       0,  7 },
        {"version",       no_argument,       0, 'V'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c, opt_idx;
    while ((c = getopt_long(argc, argv, "SLDAE:M:C:I:Vh", longopts, &opt_idx)) != -1) {
        switch (c) {
        case 'S': mode = MODE_SCAN; break;
        case 'L': mode = MODE_LIST; break;
        case 'D': mode = MODE_DETECT_RULES; break;
        case 'A': mode = MODE_AUDIT; break;
        case 'I': mode = MODE_MODULE_INFO; target = optarg; break;
        case 'E': mode = MODE_EXPLOIT; target = optarg; break;
        case 'M': mode = MODE_MITIGATE; target = optarg; break;
        case 'C': mode = MODE_CLEANUP; target = optarg; break;
        case  1 : i_know = 1; ctx.authorized = true; break;
        case  2 : ctx.active_probe = true; break;
        case  3 : ctx.no_shell = true; break;
        case  4 : ctx.json = true; break;
        case  5 : ctx.no_color = true; break;
        case  7 : ctx.full_chain = true; break;
        case  6 :
            if      (strcmp(optarg, "auditd") == 0) dr_fmt = FMT_AUDITD;
            else if (strcmp(optarg, "sigma")  == 0) dr_fmt = FMT_SIGMA;
            else if (strcmp(optarg, "yara")   == 0) dr_fmt = FMT_YARA;
            else if (strcmp(optarg, "falco")  == 0) dr_fmt = FMT_FALCO;
            else { fprintf(stderr, "[-] unknown --format: %s\n", optarg); return 1; }
            break;
        case 'V': printf("iamroot %s\n", IAMROOT_VERSION); return 0;
        case 'h': mode = MODE_HELP; break;
        default: usage(argv[0]); return 1;
        }
    }

    if (mode == MODE_HELP) {
        fputs(BANNER, stderr);
        usage(argv[0]);
        return 0;
    }

    if (!ctx.json) fputs(BANNER, stderr);

    if (mode == MODE_SCAN) return cmd_scan(&ctx);
    if (mode == MODE_LIST) return cmd_list(&ctx);
    if (mode == MODE_MODULE_INFO) return cmd_module_info(target, &ctx);
    if (mode == MODE_DETECT_RULES) return cmd_detect_rules(dr_fmt);
    if (mode == MODE_AUDIT) return cmd_audit(&ctx);

    /* --exploit / --mitigate / --cleanup all take a target */
    if (target == NULL) {
        fprintf(stderr, "[-] mode requires a module name\n");
        return 1;
    }
    const struct iamroot_module *m = iamroot_module_find(target);
    if (m == NULL) {
        fprintf(stderr, "[-] no module '%s'. Try --list.\n", target);
        return 1;
    }

    if (mode == MODE_EXPLOIT) {
        if (!i_know) {
            fprintf(stderr,
                "[-] --exploit requires --i-know. This will attempt to gain\n"
                "    root and corrupt /etc/passwd in the page cache.\n"
                "    Authorized testing only. See docs/ETHICS.md.\n");
            return 1;
        }
        return cmd_one(m, "exploit", &ctx);
    }
    if (mode == MODE_MITIGATE) return cmd_one(m, "mitigate", &ctx);
    if (mode == MODE_CLEANUP)  return cmd_one(m, "cleanup",  &ctx);

    usage(argv[0]);
    return 1;
}
