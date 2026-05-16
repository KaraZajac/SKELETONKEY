# Roadmap

What's coming next, in priority order. Dates are aspirational, not
commitments.

## Phase 0 — Bootstrap (DONE as of 2026-05-16)

- [x] Repo structure (modules/, core/, docs/, tools/, tests/)
- [x] Absorbed DIRTYFAIL as the first module
  (`modules/copy_fail_family/`)
- [x] Top-level README, CVES.md, ROADMAP.md, docs/ARCHITECTURE.md,
      docs/ETHICS.md
- [x] LICENSE (MIT)
- [x] Private GitHub repo

## Phase 1 — Make the bundling real (DONE 2026-05-16)

- [x] Top-level `iamroot` dispatcher CLI (`iamroot.c`) — module
      registry, route to module's detect/exploit
- [x] Module interface header (`core/module.h`) — standard
      `iamroot_module` struct + `iamroot_result_t` (numerically
      aligned with copy_fail_family's `df_result_t` for zero-cost
      bridging)
- [x] `core/registry.{c,h}` — flat-array registry with `find_by_name`
- [x] `modules/copy_fail_family/iamroot_modules.{c,h}` — bridge layer
      exposing 5 modules
- [x] Top-level `Makefile` that builds all modules into one binary
- [x] Smoke test: `iamroot --scan --json` produces ingest-ready JSON;
      `iamroot --list` prints the module inventory
- [ ] **Deferred to Phase 1.5**: extract `apparmor_bypass.c`,
      `exploit_su.c`, `common.c`, `fcrypt.c` into `core/` (shared
      across families). Phase 1 keeps them inside copy_fail_family/src/
      because there's only one family today; the extraction is
      mechanical and lands when a second family arrives.

## Phase 2 — Add Dirty Pipe (CVE-2022-0847) — PARTIAL (DETECT done 2026-05-16)

Public PoC, well-understood, useful for completeness — IAMROOT
without Dirty Pipe is incomplete as a "historical bundle." Affects
kernels ≤5.16.11/≤5.15.25/≤5.10.102 so coverage is older
deployments (worth bundling — many production boxes still run
these).

- [x] `modules/dirty_pipe_cve_2022_0847/` directory promoted out of
      `_stubs/`
- [x] `core/kernel_range.{c,h}` — branch-aware patched-version
      comparison (reusable by every future module)
- [x] `dirty_pipe_detect()` — kernel version check against
      branch-backport thresholds (5.10.102 / 5.15.25 / 5.16.11 / 5.17+)
- [x] Detection rules: `auditd.rules` (splice() syscall + passwd/shadow
      watches) and `sigma.yml` (non-root modification of sensitive files)
- [x] Registered in `iamroot --list` / `--scan` output. Verified on
      kernel 6.12.86 → correctly reports OK (patched).
- [ ] **Phase 1.5 / Phase 2 followup**: actual exploit. Needs
      extraction of `find_passwd_uid_field` + `try_revert_passwd_page_cache`
      + `exploit_su` into `core/` so dirty_pipe can call them without
      duplicating the copy_fail_family helpers.
- [ ] CI matrix: Ubuntu 20.04 with kernel 5.13 (vulnerable),
      Debian 11 with 5.10.0-8 (vulnerable), Debian 13 with 6.12.x
      (patched — should detect as OK)

## Phase 3 — EntryBleed (CVE-2023-0458) as stage-1 leak brick (DONE 2026-05-16)

EntryBleed is **not a standalone LPE**. It's a **kbase leak
primitive** that other modules can chain. Bundled because:

- Stage-1 of any future "build-your-own LPE" workflow
- Detection rules for KPTI side-channel attempts are useful for
  defenders
- Already works empirically on lts-6.12.88 (verified 2026-05-16)

- [x] `modules/entrybleed_cve_2023_0458/` — leak primitive + detect
- [x] Exposed as a library helper: other modules can call
      `entrybleed_leak_kbase_lib()` (declared in iamroot_modules.h)
- [x] Wired into iamroot.c registry; `iamroot --exploit entrybleed
      --i-know` produces a kbase leak. Verified on kctf-mgr:
      leaked `0xffffffff8d800000` with KASLR slide `0xc800000`.
- [x] `entry_SYSCALL_64` slot offset configurable via
      `IAMROOT_ENTRYBLEED_OFFSET` env var (default matches lts-6.12.x).
      Future enhancement: auto-detect via /boot/System.map or
      /proc/kallsyms if accessible.

## Phase 4 — CI matrix

- [ ] Distro+kernel VM matrix in GitHub Actions (Ubuntu 20.04 /
      22.04 / 24.04 / 26.04, Debian 11 / 12 / 13, Alma 8 / 9 / 10,
      Fedora 39 / 40 / 41)
- [ ] Each module's exploit runs against matched-vulnerable VMs and
      MUST land root; runs against patched VMs and MUST fail at
      detect step
- [ ] Nightly run; failures open issues automatically

## Phase 5 — Detection signature export

- [ ] `iamroot --detect-rules --format=sigma` — Sigma rules per CVE
- [ ] `--format=yara` — YARA rules for static detection of exploit
      binaries
- [ ] `--format=auditd` — auditd `.rules` snippets
- [ ] `--format=falco` — Falco rule snippets
- [ ] Sample SOC playbook in `docs/DETECTION_PLAYBOOK.md`

## Phase 6 — Mitigation mode

- [ ] `iamroot --mitigate` walks the host's vulnerabilities, applies
      temporary sysctl / module-blacklist / LSM workarounds
- [ ] Per-CVE rollback procedure if the mitigation breaks something
- [ ] Idempotent: running twice is safe

## Phase 7+ — More modules

Backfill of historical and recent LPEs as time allows:

- [ ] **CVE-2021-3493** — overlayfs nested-userns LPE
- [ ] **CVE-2021-4034** — Pwnkit (pkexec env handling)
- [ ] **CVE-2022-2588** — net/sched route4 dead UAF
- [ ] **CVE-2023-2008** — vmwgfx OOB write
- [ ] **CVE-2024-1086** — netfilter nf_tables UAF
- [ ] Fragnesia (if it lands as a CVE)
- [ ] Anything we ourselves disclose — bundled AFTER upstream patch
      ships (responsible-disclosure-first)

## Non-goals

- **No 0-day shipment.** Everything in IAMROOT is post-patch.
- **No automated mass-targeting.** No host-list mode. No automatic
  pivoting.
- **No persistence beyond `--exploit-backdoor`'s
  `/etc/passwd` overwrite**, which is overt and easily detected by
  any auditd rule we ship ourselves. Persistence-as-evasion is out
  of scope.
- **No container-runtime escapes** unless they cleanly chain to
  host-root.
- **No Windows / macOS / non-Linux targets.** Focus is the moat.
