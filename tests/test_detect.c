/*
 * tests/test_detect.c — detect() unit tests
 *
 * Each test builds a synthetic struct skeletonkey_host fingerprint
 * (vulnerable / patched / specific-gate-closed) and asserts each
 * module's detect() returns the expected verdict. Catches regressions
 * in the host-fingerprint-consuming logic across the corpus.
 *
 * Coverage today is the four modules that already consume ctx->host:
 *   - dirtydecrypt   (CVE-2026-31635)
 *   - fragnesia      (CVE-2026-46300)
 *   - pack2theroot   (CVE-2026-41651)
 *   - overlayfs      (CVE-2021-3493)
 * Coverage grows automatically as more modules migrate to ctx->host
 * (see ROADMAP "core/host" follow-up).
 *
 * Why only Linux: every module's real detect() lives inside
 * `#ifdef __linux__`; on non-Linux the stubs unconditionally return
 * PRECOND_FAIL so the tests are tautologies. The harness compiles
 * cross-platform but skips the assertions on non-Linux to keep the
 * macOS dev build green while still preventing bit-rot of the test
 * infrastructure.
 */

#include "../core/module.h"
#include "../core/host.h"
#include "../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct skeletonkey_module dirtydecrypt_module;
extern const struct skeletonkey_module fragnesia_module;
extern const struct skeletonkey_module pack2theroot_module;
extern const struct skeletonkey_module overlayfs_module;
extern const struct skeletonkey_module entrybleed_module;
extern const struct skeletonkey_module dirty_pipe_module;
extern const struct skeletonkey_module dirty_cow_module;
extern const struct skeletonkey_module ptrace_traceme_module;
extern const struct skeletonkey_module cgroup_release_agent_module;
extern const struct skeletonkey_module nf_tables_module;
extern const struct skeletonkey_module fuse_legacy_module;
extern const struct skeletonkey_module cls_route4_module;
extern const struct skeletonkey_module overlayfs_setuid_module;
extern const struct skeletonkey_module af_packet_module;
extern const struct skeletonkey_module af_packet2_module;
extern const struct skeletonkey_module af_unix_gc_module;
extern const struct skeletonkey_module netfilter_xtcompat_module;
extern const struct skeletonkey_module nft_set_uaf_module;
extern const struct skeletonkey_module nft_fwd_dup_module;
extern const struct skeletonkey_module nft_payload_module;
extern const struct skeletonkey_module stackrot_module;
extern const struct skeletonkey_module sequoia_module;
extern const struct skeletonkey_module vmwgfx_module;
extern const struct skeletonkey_module copy_fail_gcm_module;
extern const struct skeletonkey_module dirty_frag_esp_module;
extern const struct skeletonkey_module dirty_frag_esp6_module;
extern const struct skeletonkey_module dirty_frag_rxrpc_module;
extern const struct skeletonkey_module sudo_samedit_module;
extern const struct skeletonkey_module sudoedit_editor_module;
extern const struct skeletonkey_module pwnkit_module;
extern const struct skeletonkey_module sudo_chwoot_module;
extern const struct skeletonkey_module udisks_libblockdev_module;
extern const struct skeletonkey_module pintheft_module;
extern const struct skeletonkey_module mutagen_astronomy_module;
extern const struct skeletonkey_module sudo_runas_neg1_module;
extern const struct skeletonkey_module tioscpgrp_module;
extern const struct skeletonkey_module vsock_uaf_module;
extern const struct skeletonkey_module nft_pipapo_module;
extern const struct skeletonkey_module ptrace_pidfd_module;
extern const struct skeletonkey_module sudo_host_module;
extern const struct skeletonkey_module cifswitch_module;
extern const struct skeletonkey_module nft_catchall_module;

static int g_pass = 0;
static int g_fail = 0;

/* Record which modules at least one test row touched, so the harness
 * can print a "modules without direct coverage" warning at the end.
 * Linear append + scan is fine; we have <50 modules. The list is
 * static-sized at SKELETONKEY_MAX_TESTED_MODULES; bump if we ever
 * exceed it. */
#define SKELETONKEY_MAX_TESTED_MODULES 128
static const char *g_tested_modules[SKELETONKEY_MAX_TESTED_MODULES];
static size_t g_tested_count = 0;

static void mark_tested(const char *name)
{
	for (size_t i = 0; i < g_tested_count; i++)
		if (strcmp(g_tested_modules[i], name) == 0) return;
	if (g_tested_count < SKELETONKEY_MAX_TESTED_MODULES)
		g_tested_modules[g_tested_count++] = name;
}

static const char *result_str(skeletonkey_result_t r)
{
	switch (r) {
	case SKELETONKEY_OK:           return "OK";
	case SKELETONKEY_TEST_ERROR:   return "TEST_ERROR";
	case SKELETONKEY_VULNERABLE:   return "VULNERABLE";
	case SKELETONKEY_EXPLOIT_FAIL: return "EXPLOIT_FAIL";
	case SKELETONKEY_PRECOND_FAIL: return "PRECOND_FAIL";
	case SKELETONKEY_EXPLOIT_OK:   return "EXPLOIT_OK";
	}
	return "???";
}

#ifdef __linux__
/* Suppress per-module banner chatter so the test output stays tidy.
 * Modules respect ctx->json to mean "structured output mode; no banners"
 * — see each module's `if (!ctx->json) fprintf(...)` pattern. */
static void run_one(const char *test_name,
		    const struct skeletonkey_module *m,
		    const struct skeletonkey_host *h,
		    skeletonkey_result_t want)
{
	struct skeletonkey_ctx ctx = {0};
	ctx.host = h;
	ctx.json = true;        /* silence per-module log lines */

	skeletonkey_result_t got = m->detect(&ctx);
	mark_tested(m->name);
	if (got == want) {
		printf("[+] PASS  %-40s  %s → %s\n",
		       test_name, m->name, result_str(got));
		g_pass++;
	} else {
		fprintf(stderr,
			"[-] FAIL  %-40s  %s: want %s, got %s\n",
			test_name, m->name,
			result_str(want), result_str(got));
		g_fail++;
	}
}

/* mk_host: derive a fingerprint from a base + a kernel override.
 *
 * The most common new-test shape is "I want fingerprint X but with a
 * specific (major, minor, patch) — to nail a backport-boundary or
 * predates-the-bug case". Doing this with a fresh struct literal each
 * time obscures the *one* thing that's different. mk_host() does the
 * copy + overlay, named release string included.
 *
 * Returns a struct VALUE so the caller stores it in a stack local and
 * passes &h.  No heap. The release string is the caller's responsibility
 * (we don't synthesize from numerics to avoid implying a real release
 * naming convention). */
#ifdef __linux__
static struct skeletonkey_host
mk_host(struct skeletonkey_host base, int major, int minor, int patch,
        const char *release)
{
	base.kernel.major = major;
	base.kernel.minor = minor;
	base.kernel.patch = patch;
	base.kernel.release = release;
	return base;
}
#endif

/* ── fingerprints ────────────────────────────────────────────────── */

/* Linux 6.12.76 (Debian 13), no userns, no D-Bus, not Ubuntu — a
 * deliberately neutered host that lets the host-fingerprint-only
 * gates fire without falling into deeper module logic. */
static const struct skeletonkey_host h_pre7_no_userns_no_dbus = {
	.kernel  = { .major = 6, .minor = 12, .patch = 76,
		     .release = "6.12.76-test" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.distro_version_id  = "13",
	.distro_pretty      = "Debian GNU/Linux 13",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = false,
	.has_dbus_system    = false,
	.has_systemd        = true,
};

/* Fedora 43, no Debian family, userns allowed. */
static const struct skeletonkey_host h_fedora_no_debian = {
	.kernel  = { .major = 6, .minor = 14, .patch = 0,
		     .release = "6.14.0-fedora" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "fedora",
	.distro_version_id  = "43",
	.distro_pretty      = "Fedora 43",
	.is_linux           = true,
	.is_rpm_family      = true,
	.is_debian_family   = false,
	.unprivileged_userns_allowed = true,
	.has_dbus_system    = true,
	.has_systemd        = true,
};

/* Modern fingerprint with a known-vulnerable sudo (1.8.31 sits in
 * both the samedit [1.8.2, 1.9.5p1] and sudoedit_editor
 * [1.8.0, 1.9.12p2) vulnerable ranges) AND a known-vulnerable polkit
 * (0.105 is pre-0.121 fix). Used to assert the sudo/pwnkit modules
 * accept the host-fingerprint version strings and reach the
 * VULNERABLE-by-version path. */
static const struct skeletonkey_host h_vuln_sudo = {
	.kernel  = { .major = 5, .minor = 15, .patch = 0,
		     .release = "5.15.0-vulnsudo" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
	.sudo_version       = "1.8.31",
	.polkit_version     = "0.105",
};

/* Modern fingerprint with a fixed sudo (1.9.13p1 is above both
 * sudo_samedit and sudoedit_editor vulnerable ranges) AND a fixed
 * polkit (0.121 is the upstream pwnkit fix release). */
static const struct skeletonkey_host h_fixed_sudo = {
	.kernel  = { .major = 6, .minor = 12, .patch = 0,
		     .release = "6.12.0-fixedsudo" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
	.sudo_version       = "1.9.13p1",
	.polkit_version     = "0.121",
};

/* Ubuntu 24.04, userns allowed, D-Bus running, Debian family
 * (because Ubuntu has /etc/debian_version). Used as the "fragnesia
 * preconditions OK" baseline — fragnesia should NOT short-circuit
 * on userns/userspace gates here. */
static const struct skeletonkey_host h_ubuntu_24_userns_ok = {
	.kernel  = { .major = 6, .minor = 8, .patch = 0,
		     .release = "6.8.0-ubuntu" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "ubuntu",
	.distro_version_id  = "24.04",
	.distro_pretty      = "Ubuntu 24.04 LTS",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
	.has_dbus_system    = true,
	.has_systemd        = true,
};

/* Ancient kernel that predates many bugs (Linux 4.4 LTS). Useful for
 * the "kernel predates the bug → OK" path in dirty_pipe (bug
 * introduced 5.8). */
static const struct skeletonkey_host h_kernel_4_4 = {
	.kernel  = { .major = 4, .minor = 4, .patch = 0,
		     .release = "4.4.0-ancient" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
};

/* Recent kernel (Linux 6.12 LTS). Above virtually every backport
 * threshold in the corpus — modules should report OK via the
 * "patched by mainline inheritance" branch of kernel_range_is_patched. */
static const struct skeletonkey_host h_kernel_6_12 = {
	.kernel  = { .major = 6, .minor = 12, .patch = 0,
		     .release = "6.12.0-recent" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
};

/* Vulnerable-era kernel (5.14.0) with userns ENABLED. The mirror
 * of h_kernel_5_14_no_userns — for testing the VULNERABLE-by-version
 * happy path on modules whose detect() reaches VULNERABLE once both
 * version and userns gates are satisfied. Carrier file presence
 * (sudo, su, etc.) is read from the actual filesystem; in CI the
 * standard Debian containers provide those, so these tests are
 * deterministic on Linux. */
static const struct skeletonkey_host h_kernel_5_14_userns_ok = {
	.kernel  = { .major = 5, .minor = 14, .patch = 0,
		     .release = "5.14.0-vuln-userns-ok" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
};

/* Vulnerable-era kernel (5.14.0) with userns DISABLED. Most
 * netfilter / overlayfs / cgroup-class modules need both an in-range
 * kernel AND unprivileged userns. Kernel 5.14 was deliberately
 * chosen to clear every module's "predates the bug" pre-check in
 * this batch (nf_tables introduced 5.14; overlayfs_setuid 5.11;
 * cls_route4/fuse_legacy older still) while remaining below every
 * stable-branch backport entry (5.15.x / 5.18.x / 5.19.x in the
 * relevant tables). The version check therefore says "VULNERABLE by
 * version", and the userns gate fires next. */
static const struct skeletonkey_host h_kernel_5_14_no_userns = {
	.kernel  = { .major = 5, .minor = 14, .patch = 0,
		     .release = "5.14.0-vuln-no-userns" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = false,
};
#endif /* __linux__ */

/* ── tests ───────────────────────────────────────────────────────── */

static void run_all(void)
{
#ifdef __linux__
	/* dirtydecrypt: rxgk RESPONSE bug entered at 6.16.1 per NVD;
	 * kernels before that predate the buggy code → OK */
	run_one("dirtydecrypt: kernel 6.12 predates 6.16.1 → OK",
		&dirtydecrypt_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.14 (fedora) still predates 6.16.1 → OK",
		&dirtydecrypt_module, &h_fedora_no_debian,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.8 (ubuntu) still predates → OK",
		&dirtydecrypt_module, &h_ubuntu_24_userns_ok,
		SKELETONKEY_OK);

	/* fragnesia: SKBFL_SHARED_FRAG marker added in 5.11; kernels before
	 * that predate the buggy skb_try_coalesce() code → OK */
	run_one("fragnesia: kernel 4.4 predates 5.11 SKBFL_SHARED_FRAG → OK",
		&fragnesia_module, &h_kernel_4_4,
		SKELETONKEY_OK);

	/* fragnesia: userns disabled → XFRM gate closed → PRECOND_FAIL */
	run_one("fragnesia: userns_allowed=false → PRECOND_FAIL",
		&fragnesia_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_PRECOND_FAIL);

	/* pack2theroot: not Debian family → PRECOND_FAIL */
	run_one("pack2theroot: is_debian_family=false → PRECOND_FAIL",
		&pack2theroot_module, &h_fedora_no_debian,
		SKELETONKEY_PRECOND_FAIL);

	/* pack2theroot: Debian family but no D-Bus socket → PRECOND_FAIL */
	run_one("pack2theroot: has_dbus_system=false → PRECOND_FAIL",
		&pack2theroot_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_PRECOND_FAIL);

	/* overlayfs: distro != ubuntu → bug is Ubuntu-specific → OK */
	run_one("overlayfs: distro=debian → not Ubuntu → OK",
		&overlayfs_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_OK);

	run_one("overlayfs: distro=fedora → not Ubuntu → OK",
		&overlayfs_module, &h_fedora_no_debian,
		SKELETONKEY_OK);

	/* ── kernel-version-gate cases (post-migration coverage) ──── */

	/* dirty_pipe: bug introduced in 5.8; kernel 4.4 predates → OK */
	run_one("dirty_pipe: kernel 4.4 predates 5.8 → OK",
		&dirty_pipe_module, &h_kernel_4_4,
		SKELETONKEY_OK);

	/* dirty_pipe: kernel 6.12 is above every backport entry → OK */
	run_one("dirty_pipe: kernel 6.12 above all backports → OK",
		&dirty_pipe_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* dirty_cow: fix in mainline 4.9; kernel 6.12 is far above → OK */
	run_one("dirty_cow: kernel 6.12 above 4.9 fix → OK",
		&dirty_cow_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* ptrace_traceme: fix in 5.1.17; kernel 6.12 above → OK */
	run_one("ptrace_traceme: kernel 6.12 above 5.1.17 fix → OK",
		&ptrace_traceme_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* cgroup_release_agent: fix in mainline 5.17; kernel 6.12 above → OK */
	run_one("cgroup_release_agent: kernel 6.12 above 5.17 fix → OK",
		&cgroup_release_agent_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* ── userns-gate cases ───────────────────────────────────── */

	/* nf_tables: vulnerable kernel 5.10.0 + userns off → PRECOND_FAIL */
	run_one("nf_tables: vuln kernel + userns=false → PRECOND_FAIL",
		&nf_tables_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	/* fuse_legacy: vulnerable kernel + userns off → PRECOND_FAIL */
	run_one("fuse_legacy: vuln kernel + userns=false → PRECOND_FAIL",
		&fuse_legacy_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	/* cls_route4: vulnerable kernel + userns off → PRECOND_FAIL */
	run_one("cls_route4: vuln kernel + userns=false → PRECOND_FAIL",
		&cls_route4_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	/* overlayfs_setuid: vulnerable kernel (5.14, past the 5.11
	 * introduction and below every backport) + userns off
	 * → PRECOND_FAIL via userns gate */
	run_one("overlayfs_setuid: vuln kernel + userns=false → PRECOND_FAIL",
		&overlayfs_setuid_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	/* ── above-fix coverage for the remaining kernel modules ──
	 * Kernel 6.12 is above every backport entry in the corpus.
	 * For modules with a `kernel_range` table, kernel_range_is_patched
	 * inherits via the "host is newer than every entry" branch and
	 * detect() returns OK. */

	run_one("af_packet: kernel 6.12 above 4.11 fix → OK",
		&af_packet_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("af_packet2: kernel 6.12 above 5.9 fix → OK",
		&af_packet2_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("af_unix_gc: kernel 6.12 above 6.6-rc1 fix → OK",
		&af_unix_gc_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("netfilter_xtcompat: kernel 6.12 above 5.12 fix → OK",
		&netfilter_xtcompat_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("nft_set_uaf: kernel 6.12 above 6.4-rc4 fix → OK",
		&nft_set_uaf_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("nft_fwd_dup: kernel 6.12 above 5.17 fix → OK",
		&nft_fwd_dup_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("nft_payload: kernel 6.12 above 6.2-rc4 fix → OK",
		&nft_payload_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("stackrot: kernel 6.12 above 6.4-rc4 fix → OK",
		&stackrot_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("sequoia: kernel 6.12 above 5.13.4 fix → OK",
		&sequoia_module, &h_kernel_6_12, SKELETONKEY_OK);

	run_one("vmwgfx: kernel 6.12 above 6.3-rc6 fix → OK",
		&vmwgfx_module, &h_kernel_6_12, SKELETONKEY_OK);

	/* ── ancient-kernel predates coverage ────────────────────────
	 * Kernel 4.4 predates several module bugs introduced 5.x+. */

	run_one("nft_set_uaf: kernel 4.4 predates 5.1 → OK",
		&nft_set_uaf_module, &h_kernel_4_4, SKELETONKEY_OK);

	run_one("stackrot: kernel 4.4 predates 6.1 → OK",
		&stackrot_module, &h_kernel_4_4, SKELETONKEY_OK);

	/* ── copy_fail_family bridge userns gate ─────────────────────
	 * The 4 dirty_frag siblings + the GCM variant all reach the
	 * bug via XFRM-ESP / AF_RXRPC paths gated on unprivileged
	 * user-namespace creation. Bridge-layer precondition fires
	 * before delegating to the inner DIRTYFAIL detect. copy_fail
	 * itself uses AF_ALG (no userns needed) and bypasses the
	 * gate — its detect would proceed to the inner active probe. */

	run_one("copy_fail_gcm: userns_allowed=false → PRECOND_FAIL",
		&copy_fail_gcm_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	run_one("dirty_frag_esp: userns_allowed=false → PRECOND_FAIL",
		&dirty_frag_esp_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	run_one("dirty_frag_esp6: userns_allowed=false → PRECOND_FAIL",
		&dirty_frag_esp6_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	run_one("dirty_frag_rxrpc: userns_allowed=false → PRECOND_FAIL",
		&dirty_frag_rxrpc_module, &h_kernel_5_14_no_userns,
		SKELETONKEY_PRECOND_FAIL);

	/* ── userspace version fingerprinting (sudo) ─────────────────
	 * Both sudo modules now consult ctx->host->sudo_version
	 * populated once at startup. */

	/* sudo_samedit: vulnerable sudo 1.8.31 (range [1.8.2, 1.9.5p1])
	 * → VULNERABLE by version */
	run_one("sudo_samedit: sudo_version=1.8.31 → VULNERABLE",
		&sudo_samedit_module, &h_vuln_sudo,
		SKELETONKEY_VULNERABLE);

	/* sudo_samedit: fixed sudo 1.9.13p1 (above 1.9.5p1) → OK */
	run_one("sudo_samedit: sudo_version=1.9.13p1 → OK",
		&sudo_samedit_module, &h_fixed_sudo,
		SKELETONKEY_OK);

	/* pwnkit: vulnerable polkit 0.105 (pre-0.121 fix) → VULNERABLE */
	run_one("pwnkit: polkit_version=0.105 → VULNERABLE",
		&pwnkit_module, &h_vuln_sudo,
		SKELETONKEY_VULNERABLE);

	/* pwnkit: fixed polkit 0.121 → OK */
	run_one("pwnkit: polkit_version=0.121 → OK",
		&pwnkit_module, &h_fixed_sudo,
		SKELETONKEY_OK);

	/* sudoedit_editor: vulnerable sudo 1.8.31 — but the test user
	 * has no sudoers grant in the CI container, so find_sudoedit_target
	 * fails and detect short-circuits to PRECOND_FAIL ("vulnerable
	 * version present, but no sudoedit grant to abuse"). That's the
	 * documented behaviour for a non-privileged user. */
	run_one("sudoedit_editor: vuln version, no grant → PRECOND_FAIL",
		&sudoedit_editor_module, &h_vuln_sudo,
		SKELETONKEY_PRECOND_FAIL);

	/* sudoedit_editor: fixed sudo 1.9.13p1 → OK regardless of grant */
	run_one("sudoedit_editor: sudo_version=1.9.13p1 → OK",
		&sudoedit_editor_module, &h_fixed_sudo,
		SKELETONKEY_OK);

	/* ── happy-path VULNERABLE coverage ──────────────────────────
	 * Vulnerable kernel + userns allowed reaches the VULNERABLE
	 * branch on modules whose detect() short-circuits there once
	 * both gates are satisfied. Tests the affirmative verdict
	 * path, not just precondition gates. */

	run_one("nf_tables: vuln kernel 5.14 + userns ok → VULNERABLE",
		&nf_tables_module, &h_kernel_5_14_userns_ok,
		SKELETONKEY_VULNERABLE);

	run_one("cls_route4: vuln kernel 5.14 + userns ok → VULNERABLE",
		&cls_route4_module, &h_kernel_5_14_userns_ok,
		SKELETONKEY_VULNERABLE);

	run_one("nft_set_uaf: vuln kernel 5.14 + userns ok → VULNERABLE",
		&nft_set_uaf_module, &h_kernel_5_14_userns_ok,
		SKELETONKEY_VULNERABLE);

	run_one("nft_fwd_dup: vuln kernel 5.14 + userns ok → VULNERABLE",
		&nft_fwd_dup_module, &h_kernel_5_14_userns_ok,
		SKELETONKEY_VULNERABLE);

	run_one("nft_payload: vuln kernel 5.14 + userns ok → VULNERABLE",
		&nft_payload_module, &h_kernel_5_14_userns_ok,
		SKELETONKEY_VULNERABLE);

	/* ── drift-entry boundary coverage ────────────────────────────
	 * These tests guard the kernel_patched_from entries added by the
	 * tools/refresh-kernel-ranges.py drift batch (commit 8de46e2).
	 * Each entry has a "just-below" + "exact" pair so a regression
	 * that drops or off-by-ones the entry is caught immediately. */

	/* af_unix_gc {6, 4, 13} — Debian forky stable backport. The bug is
	 * reachable as a plain unprivileged user (AF_UNIX needs no caps and
	 * no userns), so 6.4.12 returns VULNERABLE rather than
	 * PRECOND_FAIL — the just-below-boundary verdict the table
	 * decides. */
	struct skeletonkey_host h_af_unix_6_4_12 =
		mk_host(h_kernel_5_14_no_userns, 6, 4, 12, "6.4.12-test");
	run_one("af_unix_gc: 6.4.12 (one below new entry) → VULNERABLE",
		&af_unix_gc_module, &h_af_unix_6_4_12,
		SKELETONKEY_VULNERABLE);

	struct skeletonkey_host h_af_unix_6_4_13 =
		mk_host(h_kernel_5_14_no_userns, 6, 4, 13, "6.4.13-test");
	run_one("af_unix_gc: 6.4.13 (exact new entry) → OK via patch table",
		&af_unix_gc_module, &h_af_unix_6_4_13,
		SKELETONKEY_OK);

	/* vmwgfx {5, 10, 127} — Debian bullseye stable backport. Below the
	 * entry, detect proceeds past the version check and fails the
	 * AF_VSOCK / /dev/dri probe in CI → PRECOND_FAIL. At the exact
	 * entry, kernel_range_is_patched short-circuits → OK. */
	struct skeletonkey_host h_vmwgfx_5_10_127 =
		mk_host(h_kernel_5_14_no_userns, 5, 10, 127, "5.10.127-test");
	run_one("vmwgfx: 5.10.127 (exact new entry) → OK via patch table",
		&vmwgfx_module, &h_vmwgfx_5_10_127,
		SKELETONKEY_OK);

	/* nft_set_uaf {5, 10, 179} (harmonised from 5.10.180) — exact entry
	 * patches via table. */
	struct skeletonkey_host h_nft_set_5_10_179 =
		mk_host(h_kernel_5_14_no_userns, 5, 10, 179, "5.10.179-test");
	run_one("nft_set_uaf: 5.10.179 (harmonised entry) → OK via patch table",
		&nft_set_uaf_module, &h_nft_set_5_10_179,
		SKELETONKEY_OK);

	/* nft_set_uaf {6, 1, 27} (harmonised from 6.1.28) — exact entry
	 * patches via table. */
	struct skeletonkey_host h_nft_set_6_1_27 =
		mk_host(h_kernel_5_14_no_userns, 6, 1, 27, "6.1.27-test");
	run_one("nft_set_uaf: 6.1.27 (harmonised entry) → OK via patch table",
		&nft_set_uaf_module, &h_nft_set_6_1_27,
		SKELETONKEY_OK);

	/* nft_payload {5, 10, 162} (harmonised from 5.10.163) — exact entry. */
	struct skeletonkey_host h_nft_payload_5_10_162 =
		mk_host(h_kernel_5_14_no_userns, 5, 10, 162, "5.10.162-test");
	run_one("nft_payload: 5.10.162 (harmonised entry) → OK via patch table",
		&nft_payload_module, &h_nft_payload_5_10_162,
		SKELETONKEY_OK);

	/* nf_tables {5, 10, 209} (harmonised from 5.10.210) — exact entry. */
	struct skeletonkey_host h_nf_tables_5_10_209 =
		mk_host(h_kernel_5_14_no_userns, 5, 10, 209, "5.10.209-test");
	run_one("nf_tables: 5.10.209 (harmonised entry) → OK via patch table",
		&nf_tables_module, &h_nf_tables_5_10_209,
		SKELETONKEY_OK);

	/* ── entrybleed: meltdown_mitigation passthrough ────────────────
	 * entrybleed reads ctx->host->meltdown_mitigation (raw sysfs line)
	 * instead of re-opening /sys/.../meltdown. Test the three branches:
	 *   - empty string ("probe failed")          → conservative VULNERABLE
	 *   - "Not affected" (Meltdown-immune CPU)   → OK
	 *   - "Mitigation: PTI" (KPTI on, vulnerable) → VULNERABLE
	 * The module is x86_64-only; on other arches the stub returns
	 * PRECOND_FAIL regardless of meltdown status. We test the x86_64
	 * branch via the synthetic host's `arch` field. */
#if defined(__x86_64__) || defined(__amd64__)
	struct skeletonkey_host h_entry_no_data = h_kernel_6_12;
	h_entry_no_data.meltdown_mitigation[0] = '\0';
	run_one("entrybleed: meltdown probe unread → conservative VULNERABLE",
		&entrybleed_module, &h_entry_no_data,
		SKELETONKEY_VULNERABLE);

	struct skeletonkey_host h_entry_immune = h_kernel_6_12;
	strcpy(h_entry_immune.meltdown_mitigation, "Not affected");
	run_one("entrybleed: meltdown=Not affected (immune CPU) → OK",
		&entrybleed_module, &h_entry_immune,
		SKELETONKEY_OK);

	struct skeletonkey_host h_entry_kpti = h_kernel_6_12;
	strcpy(h_entry_kpti.meltdown_mitigation, "Mitigation: PTI");
	run_one("entrybleed: meltdown=Mitigation: PTI → VULNERABLE",
		&entrybleed_module, &h_entry_kpti,
		SKELETONKEY_VULNERABLE);
#else
	/* On non-x86_64 dev / CI containers, the stubbed detect() returns
	 * PRECOND_FAIL regardless of meltdown_mitigation contents. */
	run_one("entrybleed: non-x86_64 arch → PRECOND_FAIL (stub)",
		&entrybleed_module, &h_kernel_6_12,
		SKELETONKEY_PRECOND_FAIL);
#endif

	/* ── new v0.8.0 modules ──────────────────────────────────────── */

	/* sudo_chwoot: vulnerable sudo version range [1.9.14, 1.9.17p0].
	 * Vulnerability is independent of kernel — pure version gate.
	 * Test fingerprints below the range, in the range, and above. */
	struct skeletonkey_host h_sudo_chwoot_vuln = h_kernel_6_12;
	strcpy(h_sudo_chwoot_vuln.sudo_version, "1.9.16");
	run_one("sudo_chwoot: sudo 1.9.16 (in range) → VULNERABLE",
		&sudo_chwoot_module, &h_sudo_chwoot_vuln,
		SKELETONKEY_VULNERABLE);

	struct skeletonkey_host h_sudo_chwoot_fixed = h_kernel_6_12;
	strcpy(h_sudo_chwoot_fixed.sudo_version, "1.9.17p1");
	run_one("sudo_chwoot: sudo 1.9.17p1 (fixed) → OK",
		&sudo_chwoot_module, &h_sudo_chwoot_fixed,
		SKELETONKEY_OK);

	struct skeletonkey_host h_sudo_chwoot_old = h_kernel_6_12;
	strcpy(h_sudo_chwoot_old.sudo_version, "1.9.13p1");
	run_one("sudo_chwoot: sudo 1.9.13p1 (pre-chroot feature) → OK",
		&sudo_chwoot_module, &h_sudo_chwoot_old,
		SKELETONKEY_OK);

	/* udisks_libblockdev: detect gates on udisksd binary + dbus
	 * socket presence + active polkit session. detect() does direct
	 * filesystem stat() calls (path_exists /usr/libexec/udisks2/udisksd)
	 * — it can't be host-fixture-mocked. GHA ubuntu-24.04 runners ship
	 * udisks2 by default, so detect returns VULNERABLE there. */
	run_one("udisks_libblockdev: udisksd present on CI runner → VULNERABLE",
		&udisks_libblockdev_module, &h_kernel_6_12,
		SKELETONKEY_VULNERABLE);

	/* pintheft: AF_RDS socket() in CI/container is almost never
	 * reachable (RDS module blacklisted on every common distro except
	 * Arch) → detect returns OK ("bug exists in kernel but unreachable
	 * from userland here"). */
	run_one("pintheft: AF_RDS unreachable on CI runner → OK",
		&pintheft_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* ── v0.9.0 modules ────────────────────────────────────────── */

	/* mutagen_astronomy: kernel 6.12 is above the 4.18.8 fix → OK */
	run_one("mutagen_astronomy: kernel 6.12 above 4.18.8 fix → OK",
		&mutagen_astronomy_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* sudo_runas_neg1: fixed sudo (1.9.13p1) → OK */
	run_one("sudo_runas_neg1: sudo 1.9.13p1 above 1.8.28 fix → OK",
		&sudo_runas_neg1_module, &h_fixed_sudo,
		SKELETONKEY_OK);

	/* sudo_runas_neg1: vuln sudo 1.8.31 (in range), but no (ALL,!root)
	 * grant for this test user → OK. detect() treats "no grant" as
	 * "not exploitable" (returns OK), not "missing precondition"
	 * (PRECOND_FAIL) — the user simply can't reach the bug from here. */
	run_one("sudo_runas_neg1: vuln sudo, no (ALL,!root) grant → OK",
		&sudo_runas_neg1_module, &h_vuln_sudo,
		SKELETONKEY_OK);

	/* tioscpgrp: kernel 6.12 above the 5.10 mainline fix → OK */
	run_one("tioscpgrp: kernel 6.12 above 5.10 fix → OK",
		&tioscpgrp_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* vsock_uaf: kernel 6.12 above 6.11 mainline fix → OK */
	run_one("vsock_uaf: kernel 6.12 above 6.11 fix → OK",
		&vsock_uaf_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* nft_pipapo: kernel 6.12 above 6.8 mainline fix → OK */
	run_one("nft_pipapo: kernel 6.12 above 6.8 fix → OK",
		&nft_pipapo_module, &h_kernel_6_12,
		SKELETONKEY_OK);

	/* nft_pipapo: kernel 5.4 predates the pipapo set type (5.6+) → OK */
	run_one("nft_pipapo: kernel 4.4 predates pipapo (5.6+) → OK",
		&nft_pipapo_module, &h_kernel_4_4,
		SKELETONKEY_OK);

	/* ── ptrace_pidfd (CVE-2026-46333) ───────────────────────────
	 * Version-pinned: predates-gate at pidfd_getfd's 5.6 introduction,
	 * then Debian backports 5.10.251 / 6.1.172 / 6.12.88 / 7.0.7. */

	/* kernel 4.4 predates the pidfd_getfd vector (added 5.6) → OK */
	run_one("ptrace_pidfd: kernel 4.4 predates pidfd_getfd (5.6) → OK",
		&ptrace_pidfd_module, &h_kernel_4_4,
		SKELETONKEY_OK);

	/* 5.5.99 is one below the 5.6 vector introduction → OK */
	struct skeletonkey_host h_pidfd_5_5_99 =
		mk_host(h_kernel_6_12, 5, 5, 99, "5.5.99-test");
	run_one("ptrace_pidfd: 5.5.99 below pidfd_getfd (5.6) → OK",
		&ptrace_pidfd_module, &h_pidfd_5_5_99,
		SKELETONKEY_OK);

	/* 5.15.5 has the vector and is below every fix backport → VULNERABLE */
	struct skeletonkey_host h_pidfd_5_15_5 =
		mk_host(h_kernel_6_12, 5, 15, 5, "5.15.5-test");
	run_one("ptrace_pidfd: 5.15.5 (vector + below all fixes) → VULNERABLE",
		&ptrace_pidfd_module, &h_pidfd_5_15_5,
		SKELETONKEY_VULNERABLE);

	/* 6.12.87 one below the trixie backport → VULNERABLE */
	struct skeletonkey_host h_pidfd_6_12_87 =
		mk_host(h_kernel_6_12, 6, 12, 87, "6.12.87-test");
	run_one("ptrace_pidfd: 6.12.87 (one below 6.12.88 backport) → VULNERABLE",
		&ptrace_pidfd_module, &h_pidfd_6_12_87,
		SKELETONKEY_VULNERABLE);

	/* 6.12.88 exact trixie backport → OK via patch table */
	struct skeletonkey_host h_pidfd_6_12_88 =
		mk_host(h_kernel_6_12, 6, 12, 88, "6.12.88-test");
	run_one("ptrace_pidfd: 6.12.88 (exact backport) → OK via patch table",
		&ptrace_pidfd_module, &h_pidfd_6_12_88,
		SKELETONKEY_OK);

	/* 7.1.0 is newer than every entry → mainline-inherited fix → OK */
	struct skeletonkey_host h_pidfd_7_1_0 =
		mk_host(h_kernel_6_12, 7, 1, 0, "7.1.0-test");
	run_one("ptrace_pidfd: 7.1.0 above all backports → OK (mainline inherit)",
		&ptrace_pidfd_module, &h_pidfd_7_1_0,
		SKELETONKEY_OK);

	/* ── sudo_host (CVE-2025-32462) ──────────────────────────────
	 * Version-gated on sudo [1.8.8, 1.9.17p0]; fixed 1.9.17p1.
	 * Assumes sudo is installed on the runner (as the other sudo_*
	 * rows do — detect() PRECOND_FAILs without a setuid sudo). */

	/* vulnerable sudo 1.8.31 (in range) → VULNERABLE */
	run_one("sudo_host: sudo 1.8.31 (in range) → VULNERABLE",
		&sudo_host_module, &h_vuln_sudo,
		SKELETONKEY_VULNERABLE);

	/* fixed sudo 1.9.17p1 → OK (note: 1.9.13p1 is still vulnerable to
	 * THIS CVE, so h_fixed_sudo can't be reused here) */
	struct skeletonkey_host h_sudo_host_fixed = h_kernel_6_12;
	strcpy(h_sudo_host_fixed.sudo_version, "1.9.17p1");
	run_one("sudo_host: sudo 1.9.17p1 (fixed) → OK",
		&sudo_host_module, &h_sudo_host_fixed,
		SKELETONKEY_OK);

	/* sudo 1.8.6 predates the -h behaviour (< 1.8.8) → OK */
	struct skeletonkey_host h_sudo_host_old = h_kernel_6_12;
	strcpy(h_sudo_host_old.sudo_version, "1.8.6");
	run_one("sudo_host: sudo 1.8.6 (pre-1.8.8) → OK",
		&sudo_host_module, &h_sudo_host_old,
		SKELETONKEY_OK);

	/* sudo 1.9.17 plain (== 1.9.17p0) → VULNERABLE (fix is p1) */
	struct skeletonkey_host h_sudo_host_1917 = h_kernel_6_12;
	strcpy(h_sudo_host_1917.sudo_version, "1.9.17");
	run_one("sudo_host: sudo 1.9.17 (==p0, pre-p1 fix) → VULNERABLE",
		&sudo_host_module, &h_sudo_host_1917,
		SKELETONKEY_VULNERABLE);

	/* ── cifswitch (CVE-2026-46243) ──────────────────────────────
	 * Version-gated on Debian backports 5.10.257 / 6.1.174 / 6.12.90 /
	 * 7.0.10. The VULNERABLE/PRECOND_FAIL split below the fix depends on
	 * whether the cifs.upcall userspace path is present; we drive that
	 * deterministically with SKELETONKEY_CIFS_ASSUME_PRESENT (1=present,
	 * 0=absent) so the rows don't depend on cifs-utils being installed on
	 * the runner. Patched-kernel rows return OK before the probe, so they
	 * need no override. */

	/* patched branch (exact 6.12.90 backport) → OK regardless of cifs */
	struct skeletonkey_host h_ciw_61290 =
		mk_host(h_kernel_6_12, 6, 12, 90, "6.12.90-test");
	run_one("cifswitch: 6.12.90 (exact backport) → OK via patch table",
		&cifswitch_module, &h_ciw_61290,
		SKELETONKEY_OK);

	/* 7.1.0 newer than every entry → mainline-inherited fix → OK */
	struct skeletonkey_host h_ciw_710 =
		mk_host(h_kernel_6_12, 7, 1, 0, "7.1.0-test");
	run_one("cifswitch: 7.1.0 above all backports → OK (mainline inherit)",
		&cifswitch_module, &h_ciw_710,
		SKELETONKEY_OK);

	/* vulnerable kernel (one below 6.12.90) + cifs path present → VULNERABLE */
	struct skeletonkey_host h_ciw_61289 =
		mk_host(h_kernel_6_12, 6, 12, 89, "6.12.89-test");
	setenv("SKELETONKEY_CIFS_ASSUME_PRESENT", "1", 1);
	run_one("cifswitch: 6.12.89 + cifs.upcall present → VULNERABLE",
		&cifswitch_module, &h_ciw_61289,
		SKELETONKEY_VULNERABLE);

	/* same vulnerable kernel but cifs path absent → PRECOND_FAIL */
	setenv("SKELETONKEY_CIFS_ASSUME_PRESENT", "0", 1);
	run_one("cifswitch: 6.12.89 but cifs-utils absent → PRECOND_FAIL",
		&cifswitch_module, &h_ciw_61289,
		SKELETONKEY_PRECOND_FAIL);
	unsetenv("SKELETONKEY_CIFS_ASSUME_PRESENT");

	/* ── nft_catchall (CVE-2026-23111) ───────────────────────────
	 * Version-gated: predates-gate at catch-all set elements (~5.13),
	 * then Debian backports 6.1.164 / 6.12.71 / 7.0.10, PLUS unprivileged
	 * user_ns clone required (else PRECOND_FAIL). h_kernel_6_12 allows
	 * userns; h_kernel_5_14_no_userns denies it. */

	/* 5.12.50 predates catch-all set elements (~5.13) → OK */
	struct skeletonkey_host h_nca_512 =
		mk_host(h_kernel_6_12, 5, 12, 50, "5.12.50-test");
	run_one("nft_catchall: 5.12.50 predates catch-all (~5.13) → OK",
		&nft_catchall_module, &h_nca_512,
		SKELETONKEY_OK);

	/* 6.1.164 exact backport → OK via patch table */
	struct skeletonkey_host h_nca_61164 =
		mk_host(h_kernel_6_12, 6, 1, 164, "6.1.164-test");
	run_one("nft_catchall: 6.1.164 (exact backport) → OK via patch table",
		&nft_catchall_module, &h_nca_61164,
		SKELETONKEY_OK);

	/* 7.1.0 newer than every entry → mainline-inherited fix → OK */
	struct skeletonkey_host h_nca_710 =
		mk_host(h_kernel_6_12, 7, 1, 0, "7.1.0-test");
	run_one("nft_catchall: 7.1.0 above all backports → OK (mainline inherit)",
		&nft_catchall_module, &h_nca_710,
		SKELETONKEY_OK);

	/* 6.1.163 (one below the 6.1.164 backport) + userns → VULNERABLE */
	struct skeletonkey_host h_nca_61163 =
		mk_host(h_kernel_6_12, 6, 1, 163, "6.1.163-test");
	run_one("nft_catchall: 6.1.163 + userns allowed → VULNERABLE",
		&nft_catchall_module, &h_nca_61163,
		SKELETONKEY_VULNERABLE);

	/* 6.12.70 (one below the 6.12.71 backport) + userns → VULNERABLE */
	struct skeletonkey_host h_nca_61270 =
		mk_host(h_kernel_6_12, 6, 12, 70, "6.12.70-test");
	run_one("nft_catchall: 6.12.70 + userns allowed → VULNERABLE",
		&nft_catchall_module, &h_nca_61270,
		SKELETONKEY_VULNERABLE);

	/* same vulnerable kernel but unprivileged userns denied → PRECOND_FAIL */
	struct skeletonkey_host h_nca_nouserns =
		mk_host(h_kernel_5_14_no_userns, 6, 1, 163, "6.1.163-nouserns-test");
	run_one("nft_catchall: 6.1.163 but userns denied → PRECOND_FAIL",
		&nft_catchall_module, &h_nca_nouserns,
		SKELETONKEY_PRECOND_FAIL);

	/* ── coverage report ─────────────────────────────────────────
	 * Iterate the runtime registry (populated by skeletonkey_register_*
	 * calls in main()) and warn for any module that was not touched
	 * by at least one run_one() row above. Doesn't fail CI — listing
	 * is informational so we can grow coverage incrementally without
	 * blocking the build. */
	{
		size_t n_reg = skeletonkey_module_count();
		size_t missing = 0;
		for (size_t i = 0; i < n_reg; i++) {
			const struct skeletonkey_module *m =
				skeletonkey_module_at(i);
			if (!m) continue;
			bool found = false;
			for (size_t j = 0; j < g_tested_count; j++) {
				if (strcmp(g_tested_modules[j], m->name) == 0) {
					found = true; break;
				}
			}
			if (!found) {
				if (missing++ == 0) {
					fprintf(stderr,
					    "\n[i] coverage: module(s) without "
					    "a direct detect() test row:\n");
				}
				fprintf(stderr, "       - %s\n", m->name);
			}
		}
		if (missing) {
			fprintf(stderr, "[i] coverage: total %zu module(s) "
				"need test rows (registry has %zu, tests touched %zu)\n",
				missing, n_reg, g_tested_count);
		} else {
			fprintf(stderr, "[i] coverage: every registered module "
				"has at least one direct test row (%zu/%zu)\n",
				g_tested_count, n_reg);
		}
	}
#else
	fprintf(stderr, "[i] non-Linux platform: detect() bodies are stubbed; "
			"tests skipped (would tautologically pass).\n");
#endif
}

int main(void)
{
	fprintf(stderr, "=== SKELETONKEY detect() unit tests ===\n\n");

	/* Populate the runtime registry so the post-run coverage report
	 * can iterate every module the main binary would. Same call used
	 * by skeletonkey.c main(). */
	skeletonkey_register_all_modules();

	run_all();
	fprintf(stderr, "\n=== RESULTS: %d passed, %d failed ===\n",
		g_pass, g_fail);
	return g_fail ? 1 : 0;
}
