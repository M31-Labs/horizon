# Helper registry regeneration

`internal/registry/helpers-v1.json` is hand-curated. This document
describes the developer workflow for refreshing those annotations
against a newer libbpf release using `cmd/hzn-helpergen`.

## What the tool does

`hzn-helpergen` fetches a pinned `bpf_helper_defs.h` from libbpf
upstream, parses every `static <ret> (* const bpf_<name>)(...) =
(void *) <id>;` declaration into a `LibbpfHelper`, then either:

- **`check`** — compares the parsed set against the on-disk Horizon
  registry and exits non-zero with a diff if any Horizon-annotated
  `kernel_symbol` is missing from libbpf or renamed.
- **`emit -o <path>`** — writes a candidate `RegistryDoc` (the existing
  `helpers` array plus a new `candidates` array of every libbpf helper
  Horizon does NOT yet annotate) for a human to review.

The tool **never** writes to `internal/registry/helpers-v1.json`. The
hand-curated registry is the source of truth; the tool surfaces drift,
the operator merges by hand.

## When to bump the pin

Bump the four pin consts in `cmd/hzn-helpergen/pin.go` when:

- A new libbpf release ships and you want to audit what changed.
- A user reports a helper Horizon doesn't support yet — running
  `hzn-helpergen emit` against the current pin tells you whether the
  helper exists in libbpf and what its kernel symbol is.
- Nightly verification (`make helpergen-check`, run manually since it
  isn't in `make ci-go`) fails because the pinned commit's SHA256 no
  longer matches — usually means GitHub re-mirrored the file or the
  pinned commit was force-pushed off the branch.

## Bumping the pin

1. Pick the new libbpf commit. Almost always a release-tag commit, not a
   `main` tip. Resolve the tag to its commit SHA via:
   ```sh
   curl -fsSL https://api.github.com/repos/libbpf/libbpf/git/refs/tags/v1.X.Y \
     | jq -r '.object.sha'
   ```
2. Download the header at that commit:
   ```sh
   curl -fsSL \
     https://raw.githubusercontent.com/libbpf/libbpf/<sha>/src/bpf_helper_defs.h \
     -o /tmp/bpf_helper_defs.h
   ```
3. Compute its sha256:
   ```sh
   sha256sum /tmp/bpf_helper_defs.h
   ```
4. Update `cmd/hzn-helpergen/pin.go` with the new `LibbpfCommit` and
   `LibbpfHelperDefsSHA256`.
5. Run `go run ./cmd/hzn-helpergen verify` — should succeed.
6. Run `go run ./cmd/hzn-helpergen check` — surfaces any drift the
   release introduced.

## Path note (O-2 resolution)

The plan originally referenced `tools/lib/bpf/bpf_helper_defs.h`. That
is the old in-kernel mirror location. Modern libbpf releases (≥ v0.6)
ship the file at `src/bpf_helper_defs.h`. `cmd/hzn-helpergen/pin.go`
uses the modern path via `LibbpfHelperDefsPath`. Sanity-check by
opening `https://github.com/libbpf/libbpf/blob/<tag>/src/bpf_helper_defs.h`
in a browser when bumping the pin.

## Second-file note (O-9 resolution)

The plan §Q3 proposed a second sha256 for `src/bpf_helpers.h` (called
`LibbpfHelpersTxtSHA256`). On inspection that file is a user-facing
macro/type-import header that only `#includes "bpf_helper_defs.h"` — the
parser doesn't consume it. The second pin would be one more thing to
re-verify on every nightly run with no signal value. Dropped at pin time;
documented here for future plan revisions.

## CI integration policy

`hzn-helpergen` is **not wired into `make ci-go`**. Reasons:

- It requires network access to `raw.githubusercontent.com`.
- A transient GitHub outage would fail unrelated PR builds.
- Helper annotations don't drift on the PR timescale — drift detection
  is a release-engineering concern, not a per-PR concern.

`make helpergen-check` and `make helpergen-emit` are developer
entry points. A nightly job (out of scope for this Phase) is the
appropriate place to wire `helpergen-check` into automation.

## Reconciling a diff

When `hzn-helpergen check` exits non-zero:

1. Read the unified diff. Each line is one of:
   - `- bpf_<sym>` — Horizon annotates this kernel symbol but libbpf
     no longer exports it at the pinned commit. Either Horizon's
     `kernel_symbol` is a typo, or libbpf renamed/removed the helper.
   - `+ bpf_<sym>` — libbpf added a helper Horizon doesn't yet
     annotate. Decide whether Horizon should adopt it; if so, add an
     entry to `internal/registry/helpers-v1.json` (and to the Hyphae
     canonical source — drift test enforces byte equality).
   - `~ bpf_<sym>` — the surface `Name` on the two sides differs.
     Usually means a hand-curated rename happened upstream; reconcile
     by matching the registry.
2. If reconciliation requires changes to the parser's matching rules
   (e.g. libbpf introduces a new declaration shape), update
   `cmd/hzn-helpergen/parse.go` and its tests. **Do not** rewrite the
   hand-curated registry to fit the tool — the registry is the source
   of truth.
