# Ethics, scope, and acceptable use

## Acceptable use

SKELETONKEY is intended for:

1. **Authorized red-team / pentest engagements.** You have a written
   scope, signed by someone who can authorize testing on the target
   systems.
2. **Defensive teams testing detection coverage.** You're using
   SKELETONKEY in a lab to verify your auditd/sigma/falco rules fire as
   expected.
3. **Security researchers studying historical LPEs.** You're reading
   the code, running it in your own VMs, learning how the primitives
   actually work end-to-end.
4. **Build engineers verifying patch coverage.** You're running
   `skeletonkey --scan` against your fleet's golden images to confirm
   each known CVE shows up as patched.

## Not-acceptable use

SKELETONKEY should not be used:

1. On systems you do not own and have not been authorized to test
2. As part of unauthorized access to any system
3. To exfiltrate data or maintain persistence on a system after a
   testing engagement is complete
4. To build a worm, scanner, or any tool that automatically targets
   systems at scale without per-target authorization

By using SKELETONKEY you assert that your use falls into the
acceptable-use cases above.

## Why this is publishable

Every CVE bundled in SKELETONKEY is:

- **Already patched** in upstream mainline kernel
- **Already published** in NVD or distro security trackers
- **Already covered** by existing public PoCs

SKELETONKEY does not introduce new offensive capability. It bundles,
documents, and CI-tests what is already public — and ships the
detection signatures defenders need to spot it.

The bundling itself raises the baseline competence required to
benefit from this code: a script kiddie can already find and run
single-CVE PoCs on GitHub. Bundling improves quality and CI coverage
without meaningfully changing offensive capability, while providing
real defensive value through the detection-rule exports.

## Disclosure

If you find a bug in SKELETONKEY itself (incorrect detection, broken
exploit on a kernel where it should work, missing a backport in the
range metadata): file a public GitHub issue.

If you find a **new 0-day kernel LPE while inspired by reading
SKELETONKEY code**: please disclose it responsibly to the kernel
security team (`security@kernel.org`) and the affected distros
*before* writing a public PoC. Once upstream patch ships and a CVE
is assigned, SKELETONKEY will gladly accept the module.

## Persistence and stealth are out of scope

`--exploit-backdoor` in the copy_fail module overwrites a
`/etc/passwd` line with a `uid=0` shell account. This is **overt**:

- The username is `skeletonkey` (was `dirtyfail`) — instantly identifiable
- It's covered by the auditd rules SKELETONKEY ships
- `--cleanup-backdoor` restores the original line

If you're looking for evasion, persistence, or stealth: not here.
Use a real C2 framework if you have authorization to do so. SKELETONKEY
stops at "demonstrate that the bug works."
