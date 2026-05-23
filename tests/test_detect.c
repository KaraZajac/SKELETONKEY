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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct skeletonkey_module dirtydecrypt_module;
extern const struct skeletonkey_module fragnesia_module;
extern const struct skeletonkey_module pack2theroot_module;
extern const struct skeletonkey_module overlayfs_module;
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

static int g_pass = 0;
static int g_fail = 0;

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
	/* dirtydecrypt: kernel.major < 7 → predates the bug → OK */
	run_one("dirtydecrypt: kernel 6.12 predates 7.0 → OK",
		&dirtydecrypt_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.14 (fedora) still predates → OK",
		&dirtydecrypt_module, &h_fedora_no_debian,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.8 (ubuntu) still predates → OK",
		&dirtydecrypt_module, &h_ubuntu_24_userns_ok,
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
#else
	fprintf(stderr, "[i] non-Linux platform: detect() bodies are stubbed; "
			"tests skipped (would tautologically pass).\n");
#endif
}

int main(void)
{
	fprintf(stderr, "=== SKELETONKEY detect() unit tests ===\n\n");
	run_all();
	fprintf(stderr, "\n=== RESULTS: %d passed, %d failed ===\n",
		g_pass, g_fail);
	return g_fail ? 1 : 0;
}
