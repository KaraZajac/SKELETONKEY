/*
 * SKELETONKEY — top-level dispatcher
 *
 * Usage:
 *   skeletonkey --scan                    # run every module's detect()
 *   skeletonkey --scan --json             # machine-readable output
 *   skeletonkey --scan --active           # invasive probes (still no /etc/passwd writes)
 *   skeletonkey --list                    # list registered modules
 *   skeletonkey --exploit <name> --i-know # run a named module's exploit
 *   skeletonkey --mitigate <name>         # apply a temporary mitigation
 *   skeletonkey --cleanup <name>          # undo --exploit or --mitigate side effects
 *
 * Phase 1 scope: thin dispatcher over the copy_fail_family bridge.
 * Future phases add: --detect-rules export, multi-family registry,
 * fingerprint pre-pass, etc.
 */

#include "core/module.h"
#include "core/registry.h"
#include "core/offsets.h"
#include "core/host.h"
#include "core/cve_metadata.h"
#include "core/verifications.h"

#include <time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SKELETONKEY_VERSION "0.9.9"

static const char BANNER[] =
"\n"
"SKELETONKEY — Curated Linux kernel LPE corpus — v" SKELETONKEY_VERSION "\n"
"AUTHORIZED TESTING ONLY — see docs/ETHICS.md\n"
"\n";

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
"  --explain <name>      one-page operator briefing: CVE / CWE / ATT&CK /\n"
"                        KEV, host fingerprint, live detect() trace + verdict,\n"
"                        OPSEC footprint, detection coverage, mitigation.\n"
"                        Useful for triage tickets and SOC analyst handoffs.\n"
"  --auto                scan host, rank vulnerable modules by safety, run the\n"
"                        safest exploit. Requires --i-know. The 'one command\n"
"                        that gets you root' mode — picks structural exploits\n"
"                        (no kernel state touched) over page-cache writes over\n"
"                        kernel primitives over races.\n"
"  --audit               system-hygiene scan: setuid binaries, world-writable\n"
"                        files in /etc, file capabilities, sudo NOPASSWD\n"
"                        (complements --scan; answers 'is this box\n"
"                        generally privesc-exposed?')\n"
"  --dump-offsets        walk /proc/kallsyms + /boot/System.map and emit a\n"
"                        C struct-entry ready to paste into core/offsets.c's\n"
"                        kernel_table[] for the --full-chain finisher.\n"
"                        Needs root (or kernel.kptr_restrict=0) to read\n"
"                        kallsyms. See docs/OFFSETS.md.\n"
"  --version             print version\n"
"  --help                this message\n"
"\n"
"Options:\n"
"  --i-know              authorization gate for --exploit modes\n"
"  --active              in --scan, do invasive sentinel probes (no /etc/passwd writes)\n"
"  --no-shell            in --exploit modes, prepare but don't drop to shell\n"
"  --dry-run             preview only — do the scan + pick, never call exploit/\n"
"                        mitigate/cleanup. Useful with --auto to see what would\n"
"                        fire before authorizing it.\n"
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
    MODE_AUTO,
    MODE_DUMP_OFFSETS,
    MODE_HELP,
    MODE_VERSION,
    MODE_EXPLAIN,
};

enum detect_format {
    FMT_AUDITD,
    FMT_SIGMA,
    FMT_YARA,
    FMT_FALCO,
};

static const char *result_str(skeletonkey_result_t r)
{
    switch (r) {
    case SKELETONKEY_OK:            return "OK";
    case SKELETONKEY_TEST_ERROR:    return "ERROR";
    case SKELETONKEY_VULNERABLE:    return "VULNERABLE";
    case SKELETONKEY_EXPLOIT_FAIL:  return "EXPLOIT_FAIL";
    case SKELETONKEY_PRECOND_FAIL:  return "PRECOND_FAIL";
    case SKELETONKEY_EXPLOIT_OK:    return "EXPLOIT_OK";
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

static void emit_module_json(const struct skeletonkey_module *m, bool include_rules)
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

    /* CVE-keyed triage metadata (CWE, ATT&CK, KEV). Sourced from CISA
     * + NVD via tools/refresh-cve-metadata.py; lookup is O(corpus). */
    const struct cve_metadata *md = cve_metadata_lookup(m->cve);
    if (md) {
        char *cwe   = json_escape(md->cwe);
        char *tech  = json_escape(md->attack_technique);
        char *sub   = json_escape(md->attack_subtechnique);
        char *kdate = json_escape(md->kev_date_added);
        fprintf(stdout,
            ",\"triage\":{\"cwe\":%s%s%s,"
            "\"attack_technique\":%s%s%s,"
            "\"attack_subtechnique\":%s%s%s,"
            "\"in_kev\":%s,"
            "\"kev_date_added\":\"%s\"}",
            cwe   ? "\"" : "", cwe   ? cwe   : "null", cwe   ? "\"" : "",
            tech  ? "\"" : "", tech  ? tech  : "null", tech  ? "\"" : "",
            sub   ? "\"" : "", sub   ? sub   : "null", sub   ? "\"" : "",
            md->in_kev ? "true" : "false",
            kdate ? kdate : "");
        free(cwe); free(tech); free(sub); free(kdate);
    }

    /* Per-module OPSEC notes — telemetry footprint of this exploit. */
    if (m->opsec_notes) {
        char *op = json_escape(m->opsec_notes);
        fprintf(stdout, ",\"opsec_notes\":\"%s\"", op ? op : "");
        free(op);
    }

    /* Architecture support for the exploit body. */
    if (m->arch_support) {
        char *a = json_escape(m->arch_support);
        fprintf(stdout, ",\"arch_support\":\"%s\"", a ? a : "");
        free(a);
    }

    /* Empirical verification records: (distro, kernel, date) tuples
     * where the module's detect() was confirmed against a real target. */
    size_t nv = 0;
    const struct verification_record *vrs = verifications_for_module(m->name, &nv);
    if (nv > 0) {
        fprintf(stdout, ",\"verified_on\":[");
        for (size_t i = 0; i < nv; i++) {
            char *vat = json_escape(vrs[i].verified_at);
            char *vkr = json_escape(vrs[i].host_kernel);
            char *vds = json_escape(vrs[i].host_distro);
            char *vbx = json_escape(vrs[i].vm_box);
            char *vst = json_escape(vrs[i].status);
            char *vac = json_escape(vrs[i].actual_detect);
            fprintf(stdout,
                "%s{\"verified_at\":\"%s\",\"host_kernel\":\"%s\","
                "\"host_distro\":\"%s\",\"vm_box\":\"%s\","
                "\"actual_detect\":\"%s\",\"status\":\"%s\"}",
                i ? "," : "",
                vat ? vat : "", vkr ? vkr : "", vds ? vds : "",
                vbx ? vbx : "", vac ? vac : "", vst ? vst : "");
            free(vat); free(vkr); free(vds); free(vbx); free(vst); free(vac);
        }
        fprintf(stdout, "]");
    }

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

static int cmd_list(const struct skeletonkey_ctx *ctx)
{
    size_t n = skeletonkey_module_count();
    if (ctx->json) {
        fprintf(stdout, "{\"version\":\"%s\",\"modules\":[", SKELETONKEY_VERSION);
        for (size_t i = 0; i < n; i++) {
            if (i) fputc(',', stdout);
            emit_module_json(skeletonkey_module_at(i), false);
        }
        fprintf(stdout, "]}\n");
        return 0;
    }
    /* The ARCH column shows where exploit() is known/expected to work:
     *   "any"  → userspace or arch-agnostic kernel primitive
     *   "x64"  → x86_64 only (entrybleed)
     *   "x64?" → x86_64 verified, arm64 untested (the honest default
     *           for kernel modules that haven't been arm64-confirmed) */
    fprintf(stdout, "%-20s %-18s %-3s %-3s %-5s %-25s %s\n",
            "NAME", "CVE", "KEV", "VFY", "ARCH", "FAMILY", "SUMMARY");
    fprintf(stdout, "%-20s %-18s %-3s %-3s %-5s %-25s %s\n",
            "----", "---", "---", "---", "----", "------", "-------");
    size_t n_kev = 0, n_vfy = 0, n_any = 0;
    for (size_t i = 0; i < n; i++) {
        const struct skeletonkey_module *m = skeletonkey_module_at(i);
        const struct cve_metadata *md = cve_metadata_lookup(m->cve);
        bool in_kev = md && md->in_kev;
        bool verified = verifications_module_has_match(m->name);
        const char *arch_abbr = "?";
        if (m->arch_support) {
            if      (strcmp(m->arch_support, "any") == 0)    { arch_abbr = "any"; n_any++; }
            else if (strcmp(m->arch_support, "x86_64") == 0) { arch_abbr = "x64"; }
            else                                              { arch_abbr = "x64?"; }
        }
        if (in_kev)   n_kev++;
        if (verified) n_vfy++;
        fprintf(stdout, "%-20s %-18s %-3s %-3s %-5s %-25s %s\n",
                m->name, m->cve,
                in_kev   ? "★" : "",
                verified ? "✓" : "",
                arch_abbr,
                m->family, m->summary);
    }
    fprintf(stdout, "\n%zu modules registered · %zu in CISA KEV (★) · "
                    "%zu empirically verified in real VMs (✓) · "
                    "%zu arch-independent (any)\n",
            n, n_kev, n_vfy, n_any);
    fprintf(stdout, "ARCH key: 'any' = userspace or arch-agnostic; "
                    "'x64' = x86_64 only; 'x64?' = x86_64 verified, "
                    "arm64 untested\n");
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

static int cmd_audit(const struct skeletonkey_ctx *ctx)
{
    int n_setuid = 0, n_ww = 0, n_cap = 0, n_sudo = 0;
    if (ctx->json) {
        fprintf(stdout, "{\"version\":\"%s\",\"audit\":[", SKELETONKEY_VERSION);
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

/* --dump-offsets: walk /proc/kallsyms + /boot/System.map for the running
 * kernel and emit a ready-to-paste C struct entry for kernel_table[] in
 * core/offsets.c. Operators run this once on a kernel they have root on
 * (or kptr_restrict=0), then upstream the entry so --full-chain works
 * out-of-the-box on that build for everyone. */
static int cmd_dump_offsets(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    struct skeletonkey_kernel_offsets off;
    int n = skeletonkey_offsets_resolve(&off);

    if (off.kbase == 0) {
        fprintf(stderr,
"[-] dump-offsets: couldn't resolve a kernel base address.\n"
"\n"
"    /proc/kallsyms returned all-zero addresses (kptr_restrict is\n"
"    enforcing). /boot/System.map-%s wasn't readable either.\n"
"\n"
"    Try one of:\n"
"      sudo skeletonkey --dump-offsets\n"
"      sudo sysctl kernel.kptr_restrict=0; skeletonkey --dump-offsets\n"
"      sudo chmod 0644 /boot/System.map-$(uname -r); skeletonkey --dump-offsets\n",
            off.kernel_release[0] ? off.kernel_release : "$(uname -r)");
        return 1;
    }
    if (n == 0) {
        fprintf(stderr,
"[-] dump-offsets: kbase resolved but no symbols. Sources tried: env,\n"
"    /proc/kallsyms, /boot/System.map. Check that the kernel symbols\n"
"    you need (modprobe_path / init_task / poweroff_cmd) actually exist\n"
"    in the symbol files.\n");
        return 1;
    }

    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);

    fprintf(stdout,
"/* Generated %04d-%02d-%02d by `skeletonkey --dump-offsets`.\n"
" * Host kernel: %s%s%s\n"
" * Resolved fields: modprobe_path=%s init_task=%s cred=%s\n"
" * Paste this entry into kernel_table[] in core/offsets.c.\n"
" */\n",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        off.kernel_release,
        off.distro[0] ? "  distro=" : "",
        off.distro[0] ? off.distro : "",
        skeletonkey_offset_source_name(off.source_modprobe),
        skeletonkey_offset_source_name(off.source_init_task),
        skeletonkey_offset_source_name(off.source_cred));

    fprintf(stdout,
"{ .release_glob       = \"%s\",\n", off.kernel_release);
    if (off.distro[0]) {
        fprintf(stdout,
"  .distro_match       = \"%s\",\n", off.distro);
    } else {
        fprintf(stdout,
"  .distro_match       = NULL,\n");
    }
    if (off.modprobe_path) {
        fprintf(stdout,
"  .rel_modprobe_path  = 0x%lx,\n",
            (unsigned long)(off.modprobe_path - off.kbase));
    }
    if (off.poweroff_cmd) {
        fprintf(stdout,
"  .rel_poweroff_cmd   = 0x%lx,\n",
            (unsigned long)(off.poweroff_cmd - off.kbase));
    }
    if (off.init_task) {
        fprintf(stdout,
"  .rel_init_task      = 0x%lx,\n",
            (unsigned long)(off.init_task - off.kbase));
    }
    if (off.init_cred) {
        fprintf(stdout,
"  .rel_init_cred      = 0x%lx,\n",
            (unsigned long)(off.init_cred - off.kbase));
    }
    if (off.cred_offset_real) {
        fprintf(stdout,
"  .cred_offset_real   = 0x%x,\n", off.cred_offset_real);
    }
    if (off.cred_offset_eff) {
        fprintf(stdout,
"  .cred_offset_eff    = 0x%x,\n", off.cred_offset_eff);
    }
    fprintf(stdout,
"},\n");

    fprintf(stderr,
"\n[+] dumped %d resolved fields. Verify offsets, then upstream this\n"
"    entry via a PR to https://github.com/KaraZajac/SKELETONKEY.\n", n);
    return 0;
}

/* --module-info <name>: dump everything we know about one module.
 * Human-readable by default, JSON with --json. Includes the full
 * detection-rule text bodies for that module. */
static int cmd_module_info(const char *name, const struct skeletonkey_ctx *ctx)
{
    const struct skeletonkey_module *m = skeletonkey_module_find(name);
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

    /* Triage metadata sourced from CISA KEV + NVD (lookup keyed by
     * m->cve). Only printed when present; mapping for older or
     * recently-disclosed CVEs may be partial. */
    const struct cve_metadata *md = cve_metadata_lookup(m->cve);
    if (md) {
        if (md->cwe)
            fprintf(stdout, "cwe:           %s\n", md->cwe);
        if (md->attack_technique)
            fprintf(stdout, "att&ck:        %s%s%s\n",
                md->attack_technique,
                md->attack_subtechnique ? " / " : "",
                md->attack_subtechnique ? md->attack_subtechnique : "");
        if (md->in_kev)
            fprintf(stdout, "in CISA KEV:   YES (added %s)\n",
                md->kev_date_added);
        else
            fprintf(stdout, "in CISA KEV:   no\n");
    }

    fprintf(stdout, "operations:    %s%s%s%s\n",
        m->detect   ? "detect "   : "",
        m->exploit  ? "exploit "  : "",
        m->mitigate ? "mitigate " : "",
        m->cleanup  ? "cleanup "  : "");
    if (m->arch_support)
        fprintf(stdout, "arch support:  %s\n", m->arch_support);
    fprintf(stdout, "detect rules:  %s%s%s%s\n",
        m->detect_auditd ? "auditd " : "",
        m->detect_sigma  ? "sigma "  : "",
        m->detect_yara   ? "yara "   : "",
        m->detect_falco  ? "falco "  : "");

    /* Verification records — VM-confirmed detect() verdicts. */
    {
        size_t nv = 0;
        const struct verification_record *vrs =
            verifications_for_module(m->name, &nv);
        if (nv > 0) {
            fprintf(stdout, "\n--- verified on ---\n");
            for (size_t i = 0; i < nv; i++) {
                const char *icon = (vrs[i].status &&
                    strcmp(vrs[i].status, "match") == 0) ? "✓" : "✗";
                fprintf(stdout, "  %s %s  %s  (kernel %s; %s; status: %s)\n",
                    icon, vrs[i].verified_at,
                    vrs[i].host_distro, vrs[i].host_kernel,
                    vrs[i].vm_box, vrs[i].status);
            }
        } else {
            fprintf(stdout, "\n--- verified on ---\n"
                "  (none yet — run  tools/verify-vm/verify.sh %s  to add one)\n",
                m->name);
        }
    }

    if (m->opsec_notes) {
        fprintf(stdout, "\n--- opsec notes ---\n%s\n", m->opsec_notes);
    }
    if (m->detect_auditd) {
        fprintf(stdout, "\n--- auditd rules ---\n%s", m->detect_auditd);
    }
    if (m->detect_sigma) {
        fprintf(stdout, "\n--- sigma rule ---\n%s", m->detect_sigma);
    }
    if (m->detect_yara) {
        fprintf(stdout, "\n--- yara rule ---\n%s", m->detect_yara);
    }
    if (m->detect_falco) {
        fprintf(stdout, "\n--- falco rule ---\n%s", m->detect_falco);
    }
    return 0;
}

/* Word-wrap a long paragraph at `width` columns, indenting every line by
 * `indent` spaces. Writes to stdout. Used by --explain to render the
 * .opsec_notes paragraph (typically 400-700 chars). */
static void print_wrapped(const char *text, int indent, int width)
{
    int col = indent;
    for (int i = 0; i < indent; i++) fputc(' ', stdout);
    const char *p = text;
    while (*p) {
        const char *word_start = p;
        while (*p && *p != ' ') p++;
        size_t word_len = (size_t)(p - word_start);
        if (col + (int)word_len > width && col > indent) {
            fputc('\n', stdout);
            for (int i = 0; i < indent; i++) fputc(' ', stdout);
            col = indent;
        }
        fwrite(word_start, 1, word_len, stdout);
        col += (int)word_len;
        while (*p == ' ') {
            if (col + 1 > width) {
                fputc('\n', stdout);
                for (int i = 0; i < indent; i++) fputc(' ', stdout);
                col = indent;
                p++;
                break;
            }
            fputc(' ', stdout);
            col++;
            p++;
        }
    }
    fputc('\n', stdout);
}

/* --explain MODULE — single-page operator briefing. Combines metadata
 * (CVE / CWE / ATT&CK / KEV), host fingerprint (kernel / arch / userns
 * gates), live detect() trace (the gates the module just walked, what
 * the verdict was and why), OPSEC footprint (telemetry the exploit
 * leaves), detection coverage (which formats have rules), and mitigation
 * guidance. The intended audience is anyone who wants ONE page that
 * answers "should we worry about this CVE here, what would patch it,
 * and what would the SOC see if someone tried it".
 *
 * detect() writes its reasoning to stderr (the normal verbose path);
 * --explain's structured framing goes to stdout. Redirect 2>&1 to merge. */
static int cmd_explain(const char *name, const struct skeletonkey_ctx *ctx)
{
    const struct skeletonkey_module *m = skeletonkey_module_find(name);
    if (!m) {
        fprintf(stderr, "[-] no module '%s'. Try --list.\n", name);
        return 1;
    }
    const struct cve_metadata *md = cve_metadata_lookup(m->cve);

    /* ── header ──────────────────────────────────────────────── */
    fprintf(stdout, "\n");
    fprintf(stdout, "════════════════════════════════════════════════════\n");
    fprintf(stdout, " %s   %s\n", m->name, m->cve);
    fprintf(stdout, "════════════════════════════════════════════════════\n");
    fprintf(stdout, " %s\n", m->summary);

    /* ── weakness ────────────────────────────────────────────── */
    fprintf(stdout, "\nWEAKNESS\n");
    if (md && md->cwe)
        fprintf(stdout, "  %s\n", md->cwe);
    else
        fprintf(stdout, "  (no NVD CWE mapping yet)\n");
    if (md && md->attack_technique)
        fprintf(stdout, "  MITRE ATT&CK: %s%s%s\n",
            md->attack_technique,
            md->attack_subtechnique ? " / "                  : "",
            md->attack_subtechnique ? md->attack_subtechnique : "");

    /* ── threat-intel context ────────────────────────────────── */
    fprintf(stdout, "\nTHREAT INTEL\n");
    if (md && md->in_kev)
        fprintf(stdout, "  ✓ In CISA Known Exploited Vulnerabilities catalog "
                        "(added %s)\n", md->kev_date_added);
    else
        fprintf(stdout, "  - Not in CISA KEV (no in-the-wild exploitation "
                        "observed by CISA)\n");
    fprintf(stdout, "  Affected: %s\n", m->kernel_range);

    /* ── host fingerprint summary ────────────────────────────── */
    if (ctx->host) {
        fprintf(stdout, "\nHOST FINGERPRINT\n");
        if (ctx->host->kernel.release && ctx->host->kernel.release[0])
            fprintf(stdout, "  kernel:        %s (%s)\n",
                    ctx->host->kernel.release, ctx->host->arch);
        if (ctx->host->distro_pretty[0])
            fprintf(stdout, "  distro:        %s\n", ctx->host->distro_pretty);
        fprintf(stdout, "  unpriv userns: %s\n",
                ctx->host->unprivileged_userns_allowed ? "ALLOWED" : "blocked");
        if (ctx->host->apparmor_restrict_userns)
            fprintf(stdout, "  apparmor:      restricts unprivileged userns\n");
        if (ctx->host->selinux_enforcing)
            fprintf(stdout, "  selinux:       enforcing\n");
        if (ctx->host->kernel_lockdown_active)
            fprintf(stdout, "  lockdown:      active\n");
    }

    /* ── live detect trace ───────────────────────────────────── */
    fprintf(stdout, "\nDETECT() TRACE (live; reads ctx->host, fires gates)\n");
    fflush(stdout);
    skeletonkey_result_t r = SKELETONKEY_TEST_ERROR;
    if (m->detect) {
        struct skeletonkey_ctx dctx = *ctx;
        dctx.json = false;  /* keep verbose stderr reasoning on */
        r = m->detect(&dctx);
        fflush(stderr);
    } else {
        fprintf(stdout, "  (this module has no detect() — no probe to run)\n");
    }

    fprintf(stdout, "\nVERDICT: %s\n", result_str(r));
    /* one-line interpretation for the operator */
    switch (r) {
    case SKELETONKEY_OK:
        fprintf(stdout, "  -> this host is patched / not applicable / immune.\n");
        break;
    case SKELETONKEY_VULNERABLE:
        fprintf(stdout, "  -> bug is reachable. The OPSEC section below shows what a "
                        "successful exploit() would leave.\n");
        break;
    case SKELETONKEY_PRECOND_FAIL:
        fprintf(stdout, "  -> a precondition check rejected this host: wrong "
                        "OS / arch, kernel out of range, a host-side gate "
                        "(userns / apparmor / selinux), or a missing carrier "
                        "file. See trace above for which check fired.\n");
        break;
    case SKELETONKEY_TEST_ERROR:
        fprintf(stdout, "  -> probe machinery failed; verdict unknown.\n");
        break;
    default: break;
    }

    /* ── OPSEC footprint ─────────────────────────────────────── */
    if (m->opsec_notes) {
        fprintf(stdout, "\nOPSEC FOOTPRINT (what exploit() leaves on this host)\n");
        print_wrapped(m->opsec_notes, 2, 76);
    }

    /* ── empirical verification records ────────────────────────── */
    {
        size_t nv = 0;
        const struct verification_record *vrs =
            verifications_for_module(m->name, &nv);
        fprintf(stdout, "\nVERIFIED ON (real-VM detect() confirmations)\n");
        if (nv == 0) {
            fprintf(stdout, "  (none yet — run  tools/verify-vm/verify.sh %s)\n",
                m->name);
        } else {
            for (size_t i = 0; i < nv; i++) {
                const char *icon = (vrs[i].status &&
                    strcmp(vrs[i].status, "match") == 0) ? "✓" : "✗";
                fprintf(stdout, "  %s %s  %s — kernel %s  (%s)\n",
                    icon, vrs[i].verified_at,
                    vrs[i].host_distro, vrs[i].host_kernel,
                    vrs[i].status);
            }
        }
    }

    /* ── detection coverage matrix ───────────────────────────── */
    fprintf(stdout, "\nDETECTION COVERAGE (rules embedded in this binary)\n");
    fprintf(stdout, "  %s auditd    %s sigma    %s yara    %s falco\n",
        m->detect_auditd ? "✓" : "·",
        m->detect_sigma  ? "✓" : "·",
        m->detect_yara   ? "✓" : "·",
        m->detect_falco  ? "✓" : "·");
    fprintf(stdout, "  (see  skeletonkey --module-info %s  for rule bodies,\n"
                    "   or   skeletonkey --detect-rules --format=auditd  for the full corpus)\n",
        m->name);

    return (int)r;
}

static int cmd_scan(const struct skeletonkey_ctx *ctx)
{
    int worst = 0;
    size_t n = skeletonkey_module_count();
    if (!ctx->json) {
        fprintf(stderr, "[*] skeletonkey scan: %zu module(s) registered\n", n);
    } else {
        fprintf(stdout, "{\"version\":\"%s\",\"modules\":[", SKELETONKEY_VERSION);
    }
    for (size_t i = 0; i < n; i++) {
        const struct skeletonkey_module *m = skeletonkey_module_at(i);
        if (m->detect == NULL) continue;
        skeletonkey_result_t r = m->detect(ctx);
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
    size_t n = skeletonkey_module_count();
    fprintf(stdout, "# SKELETONKEY detection rules — format: %s\n", fmt_names[fmt]);
    fprintf(stdout, "# Generated from %zu registered modules\n", n);
    fprintf(stdout, "# AUTHORIZED-TESTING tool; see docs/ETHICS.md\n\n");
    /* Dedup by pointer: family-shared rule strings (e.g. all 5
     * copy_fail_family modules share one auditd rule string) would
     * otherwise emit identical blocks once per module. */
    const char *seen[64] = {0};
    size_t n_seen = 0;
    int emitted = 0;
    for (size_t i = 0; i < n; i++) {
        const struct skeletonkey_module *m = skeletonkey_module_at(i);
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

/* --auto: scan, rank by safety, run safest vulnerable exploit. */
static int module_safety_rank(const char *n)
{
    /* Higher = safer. Run highest-ranked vulnerable module. */
    if (!strcmp(n, "pwnkit"))                return 100; /* userspace, no kernel */
    if (!strcmp(n, "sudoedit_editor"))       return 99;  /* structural argv */
    if (!strcmp(n, "sudo_host"))             return 96;  /* structural; needs a host-restricted sudoers rule */
    if (!strcmp(n, "cgroup_release_agent"))  return 98;  /* structural, no offsets */
    if (!strcmp(n, "overlayfs_setuid"))      return 97;  /* structural setuid */
    if (!strcmp(n, "overlayfs"))             return 96;  /* userns + xattr */
    if (!strcmp(n, "pack2theroot"))          return 95;  /* userspace D-Bus TOCTOU; dpkg + /tmp SUID footprint */
    if (!strcmp(n, "dirty_pipe"))            return 90;  /* page-cache write */
    if (!strcmp(n, "dirty_cow"))             return 89;
    if (!strncmp(n, "copy_fail", 9) ||
        !strncmp(n, "dirty_frag", 10))       return 88;  /* verified page-cache writes */
    if (!strcmp(n, "dirtydecrypt") ||
        !strcmp(n, "fragnesia"))             return 87;  /* ported page-cache writes; version-pinned detect, exploit NOT VM-verified */
    if (!strcmp(n, "ptrace_traceme"))        return 85;  /* userspace cred race */
    if (!strcmp(n, "ptrace_pidfd"))          return 84;  /* pidfd_getfd fd-steal race; ported, exploit NOT VM-verified */
    if (!strcmp(n, "sudo_samedit"))          return 80;  /* heap-tuned, may crash sudo */
    if (!strcmp(n, "af_unix_gc"))            return 25;  /* kernel race, low win% */
    if (!strcmp(n, "stackrot"))              return 15;  /* very low win% */
    if (!strcmp(n, "entrybleed"))            return 0;   /* leak only, not LPE */
    return 50; /* kernel primitives — middle of pack */
}

/* Per-detect timeout: a probe that hangs (network blocking, deadlocked
 * fork-probe, kernel-side stall) must NOT freeze --auto. 15s is well
 * above any honest active probe (fragnesia's full XFRM setup is ~500ms,
 * dirtydecrypt's rxgk handshake ~1s) but short enough that the scan
 * still finishes within ~7-8 minutes even if every module hits the cap. */
#define SKELETONKEY_DETECT_TIMEOUT_SECS 15

/* Run a module's detect() in a forked child so a SIGILL/SIGSEGV/etc.
 * in one detector cannot tear down the dispatcher. Also installs an
 * alarm(15) so a hung probe cannot stall the scan.
 *
 * The verdict travels back via the child's exit status
 * (skeletonkey_result_t values fit in 0..5). On a crash, returns
 * SKELETONKEY_TEST_ERROR; *crashed_signal is set to the terminating
 * signal (0 if exited normally), *timed_out is true if the signal
 * was SIGALRM (the detect-timeout fired).
 *
 * This matters because --auto auto-enables active probes, which can
 * exercise CPU instructions (entrybleed's prefetchnta sweep) or
 * kernel paths (XFRM ESP-in-TCP setup) that may misbehave under
 * emulation or hardened containers, or stall on a frozen socket.
 * Without isolation + timeout, one bad probe stops the whole scan
 * and the operator never sees the rest of the verdict table. */
static skeletonkey_result_t run_detect_isolated(
    const struct skeletonkey_module *m,
    const struct skeletonkey_ctx *ctx,
    int *crashed_signal,
    bool *timed_out)
{
    *crashed_signal = 0;
    *timed_out = false;
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return SKELETONKEY_TEST_ERROR;
    }
    if (pid == 0) {
        /* SIGALRM default action is termination — perfect kill-switch. */
        alarm(SKELETONKEY_DETECT_TIMEOUT_SECS);
        skeletonkey_result_t r = m->detect(ctx);
        fflush(NULL);
        _exit((int)r);
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) return SKELETONKEY_TEST_ERROR;
    if (WIFEXITED(st)) return (skeletonkey_result_t)WEXITSTATUS(st);
    if (WIFSIGNALED(st)) {
        *crashed_signal = WTERMSIG(st);
        if (*crashed_signal == SIGALRM) *timed_out = true;
    }
    return SKELETONKEY_TEST_ERROR;
}

/* Run a module callback (exploit/mitigate/cleanup) in a forked child.
 * Two crash-safety properties:
 *   - SIGSEGV/SIGILL/etc. in the callback is contained.
 *   - --auto's "try next-safest on EXPLOIT_FAIL" fallback path actually
 *     runs even if the picked exploit dies hard.
 *
 * Result communication is via a one-byte pipe with FD_CLOEXEC on the
 * write end:
 *   - If the callback returns normally, the child writes the result
 *     byte before _exit; the parent reads it. Trusted result code.
 *   - If the callback execve()s into a target (dirty_pipe → su,
 *     pack2theroot → /tmp/.suid_bash), FD_CLOEXEC closes the write
 *     end as part of the exec transfer; the parent's read() gets
 *     EOF. We then know the child exec'd code and report EXPLOIT_OK
 *     regardless of what shell exit code the exec'd-into program
 *     returns when the operator detaches.
 *   - If the child died of a signal, that's a crash; report it. */
static skeletonkey_result_t run_callback_isolated(
    const char *label,
    skeletonkey_result_t (*fn)(const struct skeletonkey_ctx *),
    const struct skeletonkey_ctx *ctx,
    int *crashed_signal,
    bool *exec_path)
{
    (void)label;
    *crashed_signal = 0;
    *exec_path = false;

    int pfd[2];
    if (pipe(pfd) < 0) {
        /* Plumbing failed — fall back to direct call. The crash-safety
         * property is degraded for this one invocation, but the
         * dispatcher would have crashed anyway if pipe() fails. */
        return fn(ctx);
    }
    /* FD_CLOEXEC: if child execve's, the kernel closes pfd[1] before
     * handing control to the new image, so the new image cannot
     * inadvertently write garbage and the parent observes EOF. */
    if (fcntl(pfd[1], F_SETFD, FD_CLOEXEC) < 0) {
        close(pfd[0]); close(pfd[1]);
        return fn(ctx);
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]); close(pfd[1]);
        perror("fork");
        return SKELETONKEY_TEST_ERROR;
    }
    if (pid == 0) {
        close(pfd[0]);
        skeletonkey_result_t r = fn(ctx);
        /* If we get here, fn didn't exec. Report the code. */
        unsigned char code = (unsigned char)r;
        ssize_t w = write(pfd[1], &code, 1);
        (void)w;
        close(pfd[1]);
        fflush(NULL);
        _exit((int)r);
    }
    close(pfd[1]);
    unsigned char code = 0;
    ssize_t n = read(pfd[0], &code, 1);
    close(pfd[0]);

    int st;
    waitpid(pid, &st, 0);

    if (n == 1)
        return (skeletonkey_result_t)code;

    /* No byte read → child either exec'd (FD_CLOEXEC closed pfd[1])
     * or crashed before reaching the write. Distinguish via wait
     * status. */
    if (WIFSIGNALED(st)) {
        *crashed_signal = WTERMSIG(st);
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    /* Normal exit without writing → must have exec'd. We achieved
     * code execution; treat as EXPLOIT_OK regardless of the shell's
     * subsequent exit code. */
    *exec_path = true;
    return SKELETONKEY_EXPLOIT_OK;
}

/* Host fingerprint parsing (ID / VERSION_ID / kernel / arch) lives in
 * core/host.c; cmd_auto consults ctx->host via the shared banner. */

static int cmd_auto(struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized && !ctx->dry_run) {
        fprintf(stderr,
"[-] --auto requires --i-know (or --dry-run for a preview that never fires).\n"
"    About to attempt root via the safest available LPE on this host.\n"
"    Authorized testing only. See docs/ETHICS.md.\n");
        return 1;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "[i] auto: already running as root; nothing to do.\n");
        return 0;
    }

    /* Active probes give --auto a more accurate verdict on modules that
     * implement them (dirty_pipe, the copy_fail family, dirtydecrypt,
     * fragnesia, overlayfs). Each per-module probe is documented safe:
     * /tmp sentinel files + fork-isolated namespace mounts. No real
     * system state is corrupted by the scan. Without this, --auto can
     * miss vulnerabilities that a version-only check would flag as
     * indeterminate (TEST_ERROR), or accept distro silent backports
     * that the version check is fooled by. */
    bool prev_active = ctx->active_probe;
    ctx->active_probe = true;

    /* Two-line host fingerprint banner (identity + capability gates). */
    skeletonkey_host_print_banner(ctx->host, ctx->json);
    fprintf(stderr, "[*] auto: active probes enabled — brief /tmp file "
                    "touches and fork-isolated namespace probes\n");
    fprintf(stderr, "[*] auto: scanning %zu modules for vulnerabilities...\n",
            skeletonkey_module_count());

    struct cand { const struct skeletonkey_module *m; int rank; } cands[64];
    int nc = 0;
    int n_vuln = 0, n_ok = 0, n_precond = 0, n_test = 0;
    int n_crash = 0, n_timeout = 0, n_other = 0;
    size_t n = skeletonkey_module_count();
    for (size_t i = 0; i < n; i++) {
        const struct skeletonkey_module *m = skeletonkey_module_at(i);
        if (!m->detect || !m->exploit) continue;
        int sig = 0;
        bool timed_out = false;
        skeletonkey_result_t r = run_detect_isolated(m, ctx, &sig, &timed_out);
        if (sig != 0) {
            const char *why = timed_out ? "timed out" : "crashed";
            fprintf(stderr, "[?] auto: %-22s detect() %s "
                            "(signal %d) — continuing\n",
                    m->name, why, sig);
            if (timed_out) n_timeout++;
            else           n_crash++;
            continue;
        }
        switch (r) {
        case SKELETONKEY_VULNERABLE:
            if (nc < 64) {
                cands[nc].m = m;
                cands[nc].rank = module_safety_rank(m->name);
                fprintf(stderr, "[+] auto: %-22s VULNERABLE (safety rank %d)\n",
                        m->name, cands[nc].rank);
                nc++;
            } else {
                fprintf(stderr, "[+] auto: %-22s VULNERABLE (overflow; not "
                                "considered for pick)\n", m->name);
            }
            n_vuln++;
            break;
        case SKELETONKEY_OK:
            fprintf(stderr, "[ ] auto: %-22s patched or not applicable\n",
                    m->name);
            n_ok++;
            break;
        case SKELETONKEY_PRECOND_FAIL:
            fprintf(stderr, "[ ] auto: %-22s precondition not met\n", m->name);
            n_precond++;
            break;
        case SKELETONKEY_TEST_ERROR:
            fprintf(stderr, "[?] auto: %-22s indeterminate "
                            "(detector could not decide)\n", m->name);
            n_test++;
            break;
        default:
            fprintf(stderr, "[?] auto: %-22s %s\n", m->name, result_str(r));
            n_other++;
            break;
        }
    }

    /* Restore caller's --active setting before we call exploit(). The
     * exploit() of each module may use ctx->active_probe with different
     * semantics than detect(); we owned this flag only for the scan. */
    ctx->active_probe = prev_active;

    fprintf(stderr, "\n[*] auto: scan summary — %d vulnerable, %d patched/"
                    "n.a., %d precondition-fail, %d indeterminate%s\n",
            n_vuln, n_ok, n_precond, n_test,
            n_other ? " (+other)" : "");
    if (n_crash > 0)
        fprintf(stderr, "[!] auto: %d module(s) crashed during detect "
                        "— dispatcher recovered via fork isolation\n", n_crash);
    if (n_timeout > 0)
        fprintf(stderr, "[!] auto: %d module(s) timed out (>%ds) during "
                        "detect — dispatcher recovered\n",
                n_timeout, SKELETONKEY_DETECT_TIMEOUT_SECS);

    if (nc == 0) {
        if (n_test > 0) {
            fprintf(stderr, "[i] auto: %d module(s) returned indeterminate. "
                            "Try `skeletonkey --exploit <name> --i-know` if "
                            "you know the host is vulnerable.\n", n_test);
        }
        fprintf(stderr, "[-] auto: no confirmed-vulnerable modules. Host "
                        "appears patched.\n");
        return 0;
    }

    /* Sort descending by rank (safest first). */
    for (int i = 0; i < nc; i++)
        for (int j = i + 1; j < nc; j++)
            if (cands[j].rank > cands[i].rank) {
                struct cand t = cands[i]; cands[i] = cands[j]; cands[j] = t;
            }

    const struct skeletonkey_module *pick = cands[0].m;

    if (ctx->dry_run) {
        fprintf(stderr,
"\n[*] auto: %d vulnerable module(s) found. Safest is '%s' (rank %d).\n"
"[*] auto: --dry-run: would launch `--exploit %s --i-know`; not firing.\n",
                nc, pick->name, cands[0].rank, pick->name);
        if (nc > 1) {
            fprintf(stderr, "[i] auto: other candidates (ranked):\n");
            for (int i = 1; i < nc; i++)
                fprintf(stderr, "      %-22s safety rank %d\n",
                        cands[i].m->name, cands[i].rank);
        }
        return 0;
    }

    fprintf(stderr,
"\n[*] auto: %d vulnerable module(s) found. Safest is '%s' (rank %d).\n"
"[*] auto: launching --exploit %s...\n\n",
            nc, pick->name, cands[0].rank, pick->name);

    int xsig = 0;
    bool exec_path = false;
    skeletonkey_result_t r = run_callback_isolated(
        "exploit", pick->exploit, ctx, &xsig, &exec_path);
    if (xsig != 0) {
        fprintf(stderr, "\n[!] auto: %s exploit crashed (signal %d) — "
                        "dispatcher recovered via fork isolation\n",
                pick->name, xsig);
    } else if (exec_path) {
        fprintf(stderr, "\n[*] auto: %s exploit transferred to spawned "
                        "target (shell exited cleanly) — EXPLOIT_OK\n",
                pick->name);
    } else {
        fprintf(stderr, "\n[*] auto: %s exploit returned %s\n",
                pick->name, result_str(r));
    }
    if (r == SKELETONKEY_EXPLOIT_OK) return 5;
    if (r == SKELETONKEY_EXPLOIT_FAIL && nc > 1) {
        fprintf(stderr, "[i] auto: %d more candidate(s) available — try one manually:\n", nc - 1);
        for (int i = 1; i < nc; i++)
            fprintf(stderr, "      skeletonkey --exploit %s --i-know\n", cands[i].m->name);
    }
    return (r == SKELETONKEY_EXPLOIT_FAIL) ? 3 : (int)r;
}

static int cmd_one(const struct skeletonkey_module *m, const char *op,
                   const struct skeletonkey_ctx *ctx)
{
    if (ctx->dry_run) {
        fprintf(stderr, "[*] %s: --dry-run: would run --%s; not firing.\n",
                m->name, op);
        return 0;
    }
    skeletonkey_result_t (*fn)(const struct skeletonkey_ctx *) = NULL;
    if (strcmp(op, "exploit") == 0)        fn = m->exploit;
    else if (strcmp(op, "mitigate") == 0)  fn = m->mitigate;
    else if (strcmp(op, "cleanup") == 0)   fn = m->cleanup;

    if (fn == NULL) {
        fprintf(stderr, "[-] module '%s' has no %s operation\n", m->name, op);
        return 1;
    }
    int sig = 0;
    bool exec_path = false;
    skeletonkey_result_t r = run_callback_isolated(op, fn, ctx, &sig, &exec_path);
    if (sig != 0)
        fprintf(stderr, "[!] %s --%s crashed (signal %d) — recovered\n",
                m->name, op, sig);
    else if (exec_path)
        fprintf(stderr, "[*] %s --%s transferred to spawned target — EXPLOIT_OK\n",
                m->name, op);
    else
        fprintf(stderr, "[*] %s --%s result: %s\n",
                m->name, op, result_str(r));
    return (int)r;
}

int main(int argc, char **argv)
{
    /* Bring up the module registry. New module families register
     * themselves via skeletonkey_register_all_modules() in
     * core/registry.c — add the new register_*() call there so the
     * test binary picks it up automatically. */
    skeletonkey_register_all_modules();

    enum mode mode = MODE_SCAN;
    struct skeletonkey_ctx ctx = {0};
    const char *target = NULL;
    int i_know = 0;

    /* Probe the host once, up front. ctx.host is a stable pointer
     * shared by every module callback; populating now means each
     * detect() sees the same fingerprint and no module has to re-do
     * uname/getpwuid/sysctl reads. See core/host.{h,c}. */
    ctx.host = skeletonkey_host_get();

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
        {"dump-offsets",  no_argument,       0,  8 },
        {"auto",          no_argument,       0,  9 },
        {"format",        required_argument, 0,  6 },
        {"i-know",        no_argument,       0,  1 },
        {"active",        no_argument,       0,  2 },
        {"no-shell",      no_argument,       0,  3 },
        {"json",          no_argument,       0,  4 },
        {"no-color",      no_argument,       0,  5 },
        {"full-chain",    no_argument,       0,  7 },
        {"dry-run",       no_argument,       0, 10 },
        {"explain",       required_argument, 0, 11 },
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
        case  8 : mode = MODE_DUMP_OFFSETS; break;
        case  9 : mode = MODE_AUTO; ctx.authorized = i_know ? true : ctx.authorized; break;
        case 10 : ctx.dry_run = true; break;
        case 11 : mode = MODE_EXPLAIN; target = optarg; break;
        case  6 :
            if      (strcmp(optarg, "auditd") == 0) dr_fmt = FMT_AUDITD;
            else if (strcmp(optarg, "sigma")  == 0) dr_fmt = FMT_SIGMA;
            else if (strcmp(optarg, "yara")   == 0) dr_fmt = FMT_YARA;
            else if (strcmp(optarg, "falco")  == 0) dr_fmt = FMT_FALCO;
            else { fprintf(stderr, "[-] unknown --format: %s\n", optarg); return 1; }
            break;
        case 'V': printf("skeletonkey %s\n", SKELETONKEY_VERSION); return 0;
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
    if (mode == MODE_EXPLAIN) return cmd_explain(target, &ctx);
    if (mode == MODE_DETECT_RULES) return cmd_detect_rules(dr_fmt);
    if (mode == MODE_AUDIT) return cmd_audit(&ctx);
    if (mode == MODE_AUTO) return cmd_auto(&ctx);
    if (mode == MODE_DUMP_OFFSETS) return cmd_dump_offsets(&ctx);

    /* --exploit / --mitigate / --cleanup all take a target */
    if (target == NULL) {
        fprintf(stderr, "[-] mode requires a module name\n");
        return 1;
    }
    const struct skeletonkey_module *m = skeletonkey_module_find(target);
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
