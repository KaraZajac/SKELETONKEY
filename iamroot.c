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

#define IAMROOT_VERSION "0.1.0-phase1"

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
"  --version             print version\n"
"  --help                this message\n"
"\n"
"Options:\n"
"  --i-know              authorization gate for --exploit modes\n"
"  --active              in --scan, do invasive sentinel probes (no /etc/passwd writes)\n"
"  --no-shell            in --exploit modes, prepare but don't drop to shell\n"
"  --json                machine-readable output (for SIEM/CI)\n"
"  --no-color            disable ANSI color codes\n"
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
    MODE_HELP,
    MODE_VERSION,
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

static int cmd_list(void)
{
    size_t n = iamroot_module_count();
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

    enum mode mode = MODE_SCAN;
    struct iamroot_ctx ctx = {0};
    const char *target = NULL;
    int i_know = 0;

    static struct option longopts[] = {
        {"scan",       no_argument,       0, 'S'},
        {"list",       no_argument,       0, 'L'},
        {"exploit",    required_argument, 0, 'E'},
        {"mitigate",   required_argument, 0, 'M'},
        {"cleanup",    required_argument, 0, 'C'},
        {"i-know",     no_argument,       0,  1 },
        {"active",     no_argument,       0,  2 },
        {"no-shell",   no_argument,       0,  3 },
        {"json",       no_argument,       0,  4 },
        {"no-color",   no_argument,       0,  5 },
        {"version",    no_argument,       0, 'V'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c, opt_idx;
    while ((c = getopt_long(argc, argv, "SLE:M:C:Vh", longopts, &opt_idx)) != -1) {
        switch (c) {
        case 'S': mode = MODE_SCAN; break;
        case 'L': mode = MODE_LIST; break;
        case 'E': mode = MODE_EXPLOIT; target = optarg; break;
        case 'M': mode = MODE_MITIGATE; target = optarg; break;
        case 'C': mode = MODE_CLEANUP; target = optarg; break;
        case  1 : i_know = 1; ctx.authorized = true; break;
        case  2 : ctx.active_probe = true; break;
        case  3 : ctx.no_shell = true; break;
        case  4 : ctx.json = true; break;
        case  5 : ctx.no_color = true; break;
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
    if (mode == MODE_LIST) return cmd_list();

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
