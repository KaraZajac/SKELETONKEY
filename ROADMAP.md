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

## Phase 1 — Make the bundling real (next session)

- [ ] Top-level `iamroot` dispatcher CLI (`iamroot.c`) — module
      registry, fingerprint, route to module's detect/exploit
- [ ] Module interface header (`core/module.h`) — standard
      `iamroot_module` struct each module exports
- [ ] Refactor `modules/copy_fail_family/` internals to expose the
      standard module interface
- [ ] Extract shared code into `core/`: `apparmor_bypass.c`,
      `exploit_su.c`, `common.c`, `fcrypt.c` (currently duplicated
      under the absorbed DIRTYFAIL tree)
- [ ] Top-level `Makefile` that builds all modules into one binary
- [ ] Smoke test: `iamroot --scan --json` on Ubuntu 26.04
      produces sensible output

## Phase 2 — Add Dirty Pipe (CVE-2022-0847)

Public PoC, well-understood, useful for completeness — IAMROOT
without Dirty Pipe is incomplete as a "historical bundle." Affects
kernels ≤5.16.11/≤5.15.25/≤5.10.102 so coverage is older
deployments (worth bundling — many production boxes still run
these).

- [ ] `modules/dirty_pipe_cve_2022_0847/` — exploit + detect + range
      metadata
- [ ] Test matrix: Ubuntu 20.04 (vulnerable kernels), Debian 11
      (vulnerable kernels), modern kernels (immune — should detect
      as patched)
- [ ] Detection rules: auditd splice/pipe write patterns

## Phase 3 — Add EntryBleed (CVE-2023-0458) as stage-1 leak brick

EntryBleed is **not a standalone LPE**. It's a **kbase leak
primitive** that other modules can chain. Bundle it because:

- Stage-1 of any future "build-your-own LPE" workflow
- Detection rules for KPTI side-channel attempts are useful for
  defenders
- Already works empirically on lts-6.12.88 (verified 2026-05-16)

- [ ] `modules/entrybleed_cve_2023_0458/` — leak primitive +
      detect-mitigations
- [ ] Exposed as a library helper: other modules can call
      `entrybleed_leak_kbase()` when they need a kbase

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
