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

- [x] Top-level `skeletonkey` dispatcher CLI (`skeletonkey.c`) — module
      registry, route to module's detect/exploit
- [x] Module interface header (`core/module.h`) — standard
      `skeletonkey_module` struct + `skeletonkey_result_t` (numerically
      aligned with copy_fail_family's `df_result_t` for zero-cost
      bridging)
- [x] `core/registry.{c,h}` — flat-array registry with `find_by_name`
- [x] `modules/copy_fail_family/skeletonkey_modules.{c,h}` — bridge layer
      exposing 5 modules
- [x] Top-level `Makefile` that builds all modules into one binary
- [x] Smoke test: `skeletonkey --scan --json` produces ingest-ready JSON;
      `skeletonkey --list` prints the module inventory
- [ ] **Deferred to Phase 1.5**: extract `apparmor_bypass.c`,
      `exploit_su.c`, `common.c`, `fcrypt.c` into `core/` (shared
      across families). Phase 1 keeps them inside copy_fail_family/src/
      because there's only one family today; the extraction is
      mechanical and lands when a second family arrives.

## Phase 2 — Add Dirty Pipe (CVE-2022-0847) — PARTIAL (DETECT done 2026-05-16)

Public PoC, well-understood, useful for completeness — SKELETONKEY
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
- [x] Registered in `skeletonkey --list` / `--scan` output. Verified on
      kernel 6.12.86 → correctly reports OK (patched).
- [x] **Phase 2 complete (2026-05-16)**: full exploit landed. Inline
      passwd-UID and page-cache-revert helpers in the module (~80 lines).
      Extraction into `core/host` is Phase 1.5 work — deferred until a
      third module needs the same helpers. (Two-of-two duplication is
      acceptable; three-of-three triggers extraction.)
- [x] Exploit refuses to fire when detect() reports patched (verified
      end-to-end on kernel 6.12.86 — refuses cleanly).
- [x] Cleanup function (`dirty_pipe --cleanup`) added: evicts
      /etc/passwd via POSIX_FADV_DONTNEED + drop_caches.
- [ ] CI matrix: Ubuntu 20.04 with kernel 5.13 (vulnerable),
      Debian 11 with 5.10.0-8 (vulnerable), Debian 13 with 6.12.x
      (patched — should detect as OK). Phase 4 work.

## Phase 3 — EntryBleed (CVE-2023-0458) as stage-1 leak brick (DONE 2026-05-16)

EntryBleed is **not a standalone LPE**. It's a **kbase leak
primitive** that other modules can chain. Bundled because:

- Stage-1 of any future "build-your-own LPE" workflow
- Detection rules for KPTI side-channel attempts are useful for
  defenders
- Already works empirically on lts-6.12.88 (verified 2026-05-16)

- [x] `modules/entrybleed_cve_2023_0458/` — leak primitive + detect
- [x] Exposed as a library helper: other modules can call
      `entrybleed_leak_kbase_lib()` (declared in skeletonkey_modules.h)
- [x] Wired into skeletonkey.c registry; `skeletonkey --exploit entrybleed
      --i-know` produces a kbase leak. Verified on kctf-mgr:
      leaked `0xffffffff8d800000` with KASLR slide `0xc800000`.
- [x] `entry_SYSCALL_64` slot offset configurable via
      `SKELETONKEY_ENTRYBLEED_OFFSET` env var (default matches lts-6.12.x).
      Future enhancement: auto-detect via /boot/System.map or
      /proc/kallsyms if accessible.

## Phase 4 — CI matrix (PARTIAL — build-check landed 2026-05-16)

- [x] `.github/workflows/build.yml`: matrix of {gcc, clang} ×
      {default, debug} builds on every push and PR. Includes smoke
      tests: `--version`, `--list`, `--scan`, `--detect-rules` in
      both auditd and sigma formats. Build failure breaks the merge
      gate. Static-build job runs continue-on-error (glibc + NSS
      issue; revisit with musl-gcc).
- [ ] Distro+kernel VM matrix in GitHub Actions (Ubuntu 20.04 /
      22.04 / 24.04 / 26.04, Debian 11 / 12 / 13, Alma 8 / 9 / 10,
      Fedora 39 / 40 / 41). Needs self-hosted runners or paid VM
      service; placeholder commented in build.yml.
- [ ] Each module's exploit runs against matched-vulnerable VMs and
      MUST land root; runs against patched VMs and MUST fail at
      detect step
- [ ] Nightly run; failures open issues automatically

## Phase 5 — Detection signature export (DONE 2026-05-16)

- [x] `skeletonkey --detect-rules --format=auditd` — embedded auditd rules
      across all modules (deduped — family-shared rules emit once)
- [x] `skeletonkey --detect-rules --format=sigma` — embedded Sigma rules
- [x] `--format=yara` and `--format=falco` flags accepted; per-module
      strings can be added when authors ship them. Currently no module
      ships YARA or Falco rules (skipped cleanly).
- [x] `struct skeletonkey_module` gained `detect_auditd`, `detect_sigma`,
      `detect_yara`, `detect_falco` fields — each NULL or pointer to
      embedded C string. Self-contained binary, no data-dir install needed.
- [ ] Sample SOC playbook in `docs/DETECTION_PLAYBOOK.md` — followup

## Phase 6 — Mitigation mode (PARTIAL — copy_fail_family bridged 2026-05-16)

- [x] copy_fail_family: `skeletonkey --mitigate copy_fail` (or any family
      member) blacklists algif_aead + esp4 + esp6 + rxrpc, sets
      `kernel.apparmor_restrict_unprivileged_userns=1`, drops page
      cache. Bridged from existing DIRTYFAIL `mitigate_apply()`.
- [x] copy_fail_family: `skeletonkey --cleanup <name>` routes by visible
      state: if `/etc/modprobe.d/dirtyfail-mitigations.conf` exists →
      `mitigate_revert()`; else evict /etc/passwd page cache. Heuristic
      sufficient for common usage patterns.
- [x] dirty_pipe: `skeletonkey --cleanup dirty_pipe` evicts /etc/passwd
      (already landed in Phase 2 complete).
- [ ] dirty_pipe `--mitigate`: only real fix is "upgrade your kernel";
      no automated mitigation possible. Document and skip.
- [ ] entrybleed `--mitigate`: same — no canonical patch; document.
- [ ] Idempotent re-run safety: copy_fail_family's apply is already
      idempotent (overwrites conf files). Re-verify per module.

## Phase 7+ — More modules (started 2026-05-16, v0.1.0 cut 2026-05-16)

Backfill of historical and recent LPEs as time allows.

**Landed in v0.1.0:**

- [x] **CVE-2016-5195** — Dirty COW: 🟢 FULL Phil-Oester-style race.
- [x] **CVE-2017-7308** — AF_PACKET TPACKET_V3: 🟡 PRIMITIVE
      (overflow + skb spray + cred-race attempt, no portable cred R/W).
- [x] **CVE-2019-13272** — PTRACE_TRACEME: 🟢 FULL jannh-style chain.
- [x] **CVE-2020-14386** — AF_PACKET tp_reserve: 🟡 PRIMITIVE-DEMO.
- [x] **CVE-2021-3493** — Ubuntu overlayfs userns: 🟢 FULL vsh-style.
- [x] **CVE-2021-4034** — Pwnkit: 🟢 FULL Qualys-style.
- [x] **CVE-2021-22555** — xt_compat heap-OOB: 🟡 PRIMITIVE (trigger
      + msg_msg cross-cache groom + MSG_COPY witness, no
      modprobe_path overwrite).
- [x] **CVE-2022-0185** — fsconfig 4k OOB: 🟡 PRIMITIVE (trigger
      + cross-cache groom + neighbour-detect, no MSG_COPY arb-read
      finisher).
- [x] **CVE-2022-0492** — cgroup_release_agent: 🟢 FULL universal
      structural exploit (no offsets, no race).
- [x] **CVE-2022-2588** — cls_route4 dangling UAF: 🟡 PRIMITIVE
      (tc/ip add+rm + msg_msg spray + classify drive, no cred chain).
- [x] **CVE-2023-0386** — overlayfs setuid copy-up: 🟢 FULL
      distro-agnostic.
- [x] **CVE-2023-3269** — StackRot: 🟡 PRIMITIVE/RACE (driver +
      groom; ~<1% race-win per run, honest in module header).
- [x] **CVE-2024-1086** — nf_tables verdict UAF: 🟡 PRIMITIVE
      (hand-rolled nfnetlink, NFT_GOTO+DROP malformed verdict,
      msg_msg kmalloc-cg-96 groom, no pipapo R/W chain).

**Landed since v0.1.0 (in the 28-module verified corpus):**

- [x] **CVE-2021-3156** — sudo Baron Samedit: 🟡 PRIMITIVE
      (`sudoedit -s` heap overflow; heap-tuned, may crash sudo).
- [x] **CVE-2021-33909** — Sequoia: 🟡 PRIMITIVE (`seq_file` size_t
      overflow → kernel stack OOB; trigger + witness, no cred chain).
- [x] **CVE-2023-22809** — sudoedit EDITOR/VISUAL argv escape: 🟢 FULL
      structural argv-injection (no kernel state, no offsets).
- [x] **CVE-2023-2008** — vmwgfx DRM bo size-validation OOB: 🟡
      PRIMITIVE (kmalloc-512 OOB + slab witness, no cred chain).

**Landed (ported from public PoC, pending VM verification — NOT part
of the 28-module verified corpus):**

- [x] **CVE-2026-46300** — Fragnesia: 🟡 XFRM ESP-in-TCP page-cache
      write. Ported from the V12 PoC; the old `_stubs/fragnesia_TBD`
      stub is retired. The stub's open question ("is the
      unprivileged-userns-netns scenario in scope?") is resolved —
      the module ships and reports `PRECOND_FAIL` when the userns gate
      is closed.
- [x] **CVE-2026-31635** — DirtyDecrypt: 🟡 rxgk missing-COW in-place
      decrypt page-cache write. Ported from the V12 PoC.
- [ ] **Verify both on a vulnerable-kernel VM**, pin the CVE fix
      commits, add `kernel_range` tables, and promote 🟡 → 🟢. Until
      then `detect()` is precondition-only (no version verdict) and
      `--auto` will not fire them blind.

**Carry-overs:**

- [ ] **CVE-2026-41651** — Pack2TheRoot (PackageKit daemon userspace
      LPE; cross-distro). Candidate — userspace LPE in the pwnkit vein.
- [ ] Anything we ourselves disclose — bundled AFTER upstream patch
      ships (responsible-disclosure-first)

## Phase 8 — Full-chain promotions (post v0.1.0)

The 14 🟡 PRIMITIVE modules each stop one or two steps short of full
cred-overwrite. Promotion to 🟢 means landing the leak → R/W →
modprobe_path-or-cred-rewrite stage on at least one tracked kernel.
None requires fresh research — each has a public reference exploit;
the work is porting the per-kernel offset dance into a portable
shape compatible with SKELETONKEY's "no-fabricated-offsets" rule (most
likely as an env-var override table per distro+kernel, with offset
auto-resolve via System.map / kallsyms when accessible).

Priority order: nf_tables (Notselwyn pipapo R/W), netfilter_xtcompat
(Andy Nguyen modprobe_path), af_packet (xairy sk_buff cred chase).
The remainder are lower priority — fuse_legacy and cls_route4 have
narrower distro reach; af_packet2 piggybacks on af_packet; stackrot's
race window makes it inherently low-yield; the nft_* family and
vmwgfx need their per-kernel offset tables built out.

The 2 ported-but-unverified modules (`dirtydecrypt`, `fragnesia`) are
**not** part of this Phase 8 promotion set — they need VM verification
and pinned fix commits first (tracked under Phase 7+ above) before any
full-chain work is meaningful.

## Non-goals

- **No 0-day shipment.** Everything in SKELETONKEY is post-patch.
- **No automated mass-targeting.** No host-list mode. No automatic
  pivoting.
- **No persistence beyond `--exploit-backdoor`'s
  `/etc/passwd` overwrite**, which is overt and easily detected by
  any auditd rule we ship ourselves. Persistence-as-evasion is out
  of scope.
- **No container-runtime escapes** unless they cleanly chain to
  host-root.
- **No Windows / macOS / non-Linux targets.** Focus is the moat.
