# Kernel-matrix (LVH) — status & operation

Internal doc. Describes the kernel-matrix CI that boots real kernels and
load-tests every example `.bpf.o` against each kernel's verifier. Not a
user-facing guide and not a roadmap.

## What it is

`hzn`'s examples are designed to be verifier-clean. The kernel-matrix proves
that against *real* kernel verifiers across four versions (5.10, 5.15, 6.1,
6.6), and simultaneously checks that Horizon's declared per-example minimum
kernel is accurate.

Kernel images come from **cilium little-vm-helper (LVH)** — no bespoke images
are built or hosted. The `complexity-test` LVH flavor is a BTF-enabled,
`bpftool`-equipped rootfs bundled with the named kernel, pinned by immutable
dated tag (and recorded digest) in `scripts/kernel-matrix/images.json`.

> History: an earlier plan expected bespoke `linux-X.Y-btf.qcow2` images
> hosted at a `M31-Labs/horizon-kernel-images` repo. That repo never existed
> and the format duplicated what LVH already maintains. The matrix was
> retargeted at LVH instead. GitHub issue #2 tracked the old corpus idea.

## Moving parts

| File | Role |
|---|---|
| `scripts/kernel-matrix/images.json` | v1 schema: `image_repo`/`image` + per-kernel `version` (dated tag), `digest` (provenance), `gate` (`required` for 6.1/6.6, `best_effort` for 5.10/5.15). |
| `.github/workflows/kernel-matrix.yml` | `build-objects` job builds `.bpf.o` + `.report.json` into `kmatrix-artifacts/`; `matrix` job boots each kernel via the `cilium/little-vm-helper` action and runs the loader + comparator. |
| `scripts/kernel-matrix/in-guest-load.sh` | Runs inside the guest: `bpftool prog loadall` per object, records `{object, loaded, log}` to a results JSON. Never fails the VM step on a rejected load — rejection is data. |
| `scripts/kernel-matrix/check-results.sh` | Host-side comparator. For each example, derives the expected outcome (`loads iff kernel >= report.summary.min_kernel`) and flags mismatches. Exits non-zero on any mismatch; the workflow's gate step decides whether that blocks. |
| `scripts/kernel-matrix/run.sh` | Local reproduction of one cell via the `lvh` CLI (needs QEMU); degrades to guidance when `lvh` is absent. |

## Why expectations are derived, not hand-written

There is no hand-maintained baseline corpus to drift. Each example's
`<stem>.report.json` already carries `summary.min_kernel` (the max of its
program/map/helper requirements). The comparator computes, per kernel:

```
expected_load = (kernel_version >= min_kernel)
```

and compares to the actual in-guest load result. A mismatch means one of two
real bugs: a verifier-clean example failed when it should load, or Horizon's
own `min_kernel` claim is wrong (loaded below its floor, or failed at/above
it). Both are worth a red.

## Running it

- **CI:** `workflow_dispatch` (Actions tab → kernel-matrix → Run). Needs a
  KVM-capable runner; the LVH action handles QEMU/TCG fallback.
- **Local:** `make build-examples OUT=kmatrix-artifacts && bash
  scripts/kernel-matrix/run.sh 6.1 kmatrix-artifacts` (requires the `lvh`
  CLI + QEMU).
- **Comparator only** (against a results file you already captured):
  `bash scripts/kernel-matrix/check-results.sh 6.1 kmatrix-artifacts kmatrix-artifacts/results.json`

## Remaining step: promote to a gate

The trigger is `workflow_dispatch`-only until the matrix is green end-to-end
on real runs (the boot path can only be validated live). Once green:

- Add `pull_request` + `push` triggers with a paths filter over everything
  that can change the produced `.bpf.o`: `examples/**`, `compiler/**`,
  `emitc/**`, `capability/**`, `internal/registry/**`, `clang/**`,
  `bindgen/**`, `Makefile`, `scripts/kernel-matrix/**`, `go.mod`, `go.sum`,
  and the workflow file. Docs / validator-precision-only changes are
  excluded — the matrix runs only when the object could shift.
- The `gate` field already encodes blocking (6.1, 6.6) vs best-effort (5.10,
  5.15); no schema change needed.

## Adjacent, not done here: verifier-message corpus

Booting real kernels also enables harvesting real verifier *messages* to
enrich the `HZN31xx` catalog (the original intent behind issue #2). That is a
separate effort that can reuse this same LVH boot path; it is not part of the
load matrix.

## Commit hygiene reminder

Buckley's commit-message generator historically emitted `Closes #N` from
parenthetical issue references. That renderer is now fixed (renders `Refs #N`;
see `m31labs-buckley/initiatives/commit-msg-safety`), but still audit
`git log -1 --format=%B HEAD` after each commit.
