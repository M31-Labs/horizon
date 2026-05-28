# Kernel-matrix handoff

This document is the pickup checklist for the kernel-matrix path that is
stubbed in v0.3. It is internal documentation: it describes the workflow
that runs when the external dependency (canned qcow2 kernel images at
`M31-Labs/horizon-kernel-images`) is satisfied. It is not a user-facing
guide and it is not a roadmap.

## What is pending

The kernel-matrix workflow (`.github/workflows/kernel-matrix.yml`) and
the matching local script (`scripts/kernel-matrix/run.sh`) need
BTF-enabled qcow2 kernel images to boot guests for the per-kernel smoke
loads. Those images are tracked at `M31-Labs/horizon-kernel-images` and
referenced from `scripts/kernel-matrix/images.json` by SHA256. Until the
images publish, the workflow stays `workflow_dispatch`-only and
`run.sh` short-circuits on the sentinel sha256 to avoid false greens or
reds.

The tracking issue for the external publication is GitHub issue #2 on
`M31-Labs/horizon` (and the same issue lives in
`M31-Labs/horizon-kernel-images` once that repository exists).

## How to detect publication

Run the same check the fir agent ran during Phase 2 plan execution:

```sh
gh api -X GET /repos/M31-Labs/horizon-kernel-images/releases \
    --jq '.[] | {tag: .tag_name, published_at: .published_at, assets: [.assets[].name]}'
```

The check passes when:

- The call returns at least one release.
- The release exposes assets matching `linux-5.10-btf.qcow2`,
  `linux-5.15-btf.qcow2`, `linux-6.1-btf.qcow2`, and
  `linux-6.6-btf.qcow2` (the four kernels in `images.json`).

If only a subset of the four kernels is available, treat the state as
"not yet published" — the matrix needs all four to be a useful
regression surface. A partial publication is acceptable as a staging
step but the full pickup waits on all four.

For the issue-side cross-check:

```sh
gh issue view 2 --repo M31-Labs/horizon --json state,title,comments
```

Issue #2 stays OPEN until the images publish and the pickup work below
lands.

## What changes when images publish

The work splits across four file groups. The canonical plan describing
each change in full lives in the Hyphae knowledge graph at
`~/.hyphae/spaces/m31labs-horizon/plans/v0.3-phase-2-fir-real-world.md`,
under Tasks 4A, 5A, and 6A. This document is a pointer; the plan is the
source of truth.

1. `scripts/kernel-matrix/capture-verifier-logs.sh` — replace the
   skeleton (currently exits 78 with a stub message) with the real
   capture body. The intended behavior is documented in the script's
   own header comment block: fetch+verify the qcow2 via the existing
   `qemu-boot.sh` cache layer, boot the guest with the `.bpf.o` build
   output mounted at `/bpfobjs`, run `bpftool prog load -d` per
   object inside the guest, and serialize each captured verifier log
   back to the host under
   `testdata/verifier-fixtures/real/<kernel>/<example>/<success|failure>/log.txt`.
   The success-vs-failure split is intentional and load-bearing for
   the host-side test harness.

2. `verifier/catalog_fixtures_test.go` and
   `verifier/real_fixtures_test.go` — extend the synthetic fixture
   walker to short-circuit on `real/` so it keeps enforcing the
   1:1 `(VC-id, fixture)` orphan-detection invariant on the synthetic
   corpus only, then add a sibling `TestVerifierCatalogRealFixtures`
   that walks the real subtree under a different invariant (parses
   without crash, diagnostic count matches `expected.json`). Real
   kernel logs do not map 1:1 to catalog entries, so they cannot
   participate in the orphan check.

3. `.github/workflows/kernel-matrix.yml` — flip the trigger from
   `workflow_dispatch`-only to `workflow_dispatch + pull_request +
   push` with a paths-filter that covers everything which can change
   the produced `.bpf.o` (`examples/**`, `compiler/**`, `emitc/**`,
   `capability/**`, `internal/registry/**`, `clang/**`, `Makefile`,
   `scripts/kernel-matrix/**`, `bindgen/**`, the workflow file
   itself, `go.mod`, `go.sum`). Docs and validator-precision-only
   changes are deliberately excluded — the matrix only runs when the
   `.bpf.o` could shift. The per-kernel `gate` field in
   `images.json` already encodes which kernels must block merge
   (`6.1`, `6.6`) versus best-effort (`5.10`, `5.15`); no schema
   change is required.

4. A new per-(example, kernel) capability-load smoke test, plus its
   expected-outcome fixtures, lands behind a `//go:build kernel_matrix`
   tag so `make ci-go` continues to pass without qemu setup. The
   workflow gains one more step that runs the tagged test, and the
   `Enforce gate` block already in the workflow takes the same
   required-vs-best-effort split through to the new step.

## Pre-flight checks before starting the pickup

- `gh auth status` must return an account with read access to
  `M31-Labs/horizon-kernel-images`. The publication check returns 404
  on missing auth, which is indistinguishable from "repo does not
  exist". If 404 surprises a reviewer, the auth state is the first
  thing to verify.
- The host kernel and qemu build need 9p virtfs support. Most
  distribution kernels and stock qemu builds carry it; verify with
  `qemu-system-x86_64 -virtfs help` returning the `local` driver.
- The guest images must carry `bpftool` on `$PATH`. This is an
  image-build requirement that lives upstream in
  `M31-Labs/horizon-kernel-images`; flag it on the publishing PR if
  any image omits it.

## Sentinel cleanup

When images publish:

- `scripts/kernel-matrix/images.json` — replace each
  `FILL_IN_AFTER_PUBLISHING_IMAGE` sentinel with the real SHA256 from
  the published release.
- `scripts/kernel-matrix/qemu-boot.sh` — replace its stub body with
  the qemu invocation block its own header documents.
- `scripts/kernel-matrix/run.sh` — drop the sha256-sentinel
  short-circuit block; the existing `qemu-boot.sh` delegation below
  it becomes live.
- `scripts/kernel-matrix/capture-verifier-logs.sh` — replace the
  `exit 78` body with the real capture per the script's header.
- `.github/workflows/kernel-matrix.yml` — flip the leading comment
  and the `on:` block per the trigger change above.

## CHANGELOG note template (when images publish)

```
### Added
- Kernel-matrix workflow now auto-triggers on PR/push with a paths
  filter, runs per-(example, kernel) capability-load smoke tests,
  and captures real-kernel verifier logs into the
  `testdata/verifier-fixtures/real/` corpus. Images published at
  `M31-Labs/horizon-kernel-images@<tag>`; sha256 sentinels in
  `scripts/kernel-matrix/images.json` replaced with the real digests.
  References #19 / #20 / #21.
```

Do not write a `Closes #N` line. Buckley's auto-message generator has a
known quirk that mis-parses parenthetical issue references as
auto-closers; audit `git log -1 --format=%B HEAD` after every commit on
the pickup branch.
