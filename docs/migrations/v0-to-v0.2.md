# Migrating from Horizon v0.1.x to v0.2

## TL;DR

Horizon v0.2 reshapes the capability manifest (v0 → v1), tightens the
validate layer in four soundness directions, adds seven new attach
surfaces, and grows the language from one-file programs to multi-file +
vendored-package builds. Only one user-visible break exists — the
capability manifest schema — and v0.2.x ships an in-memory auto-migration
shim so existing readers keep working. For per-area details,
see [`v0-to-v1-manifest.md`](v0-to-v1-manifest.md) and
[`v0.2-package-composition.md`](v0.2-package-composition.md).

## Breaking changes (require user action)

| Area | Change | Action |
|---|---|---|
| Capability manifest schema | `m31labs.dev/horizon/capability/v0` → `v1`. `danger` is now an axes triple (`mode × scope × reversibility`) rather than a flat string. | Call `capability.LoadManifest(raw)` instead of `json.Unmarshal` directly. v0 JSON auto-migrates in memory and emits an `HZN3303` deprecation warning. See [`v0-to-v1-manifest.md`](v0-to-v1-manifest.md). |
| Capability leaf word in reserved `kernel.*` namespace (already shipped in v0.1.1, reiterated here) | `kernel.*` names must end in `observe`, `mutate`, `drop`, `block`, `privileged`, `deny`, or `allow`. | Rename non-conforming capabilities (e.g., `kernel.process.exec.count` → `kernel.process.exec.count.observe`). |

There are no `.hzn` source-level breaks in Phase 1/2. Programs that
compiled under v0.1 either compile unchanged under v0.2, or fail at the
validate layer because they were unsound and the new analyses caught
it — see "Validate-layer changes" below.

## New capabilities (no user action needed)

Every item below is additive. Existing programs and manifest consumers
continue to work without modification.

### Seven new attach surfaces

| Surface | Min kernel | Example |
|---|---|---|
| `uprobe` | 4.3 | `examples/uprobeexec/` |
| `uretprobe` | 4.3 | `examples/uretprobeexec/` |
| `fentry` | 5.5 | `examples/fentryopen/` |
| `fexit` | 5.5 | `examples/fexitopen/` |
| `raw_tp` | 4.17 | `examples/rawtpenter/` |
| `sockops` | 4.13 | `examples/sockopstrack/` |
| `struct_ops` | 5.6 | `examples/structopstcp/` (attach helper stubbed; see debts) |

Registry entries: `internal/registry/capability-namespaces-v1.json`.
Surface recognition: `validate/helpers.go`. The five tracing surfaces
(`uprobe`/`uretprobe`/`fentry`/`fexit`/`raw_tp`) get `bpf.current_pid()`
and `bpf.ktime_get_ns()` automatically.

### Helper side-effect modeling

Each `Capability` in a v1 manifest may now carry an additive
`helper_effects` array describing what each program's helper calls
observe, mutate, require, and what resource verb they exercise.
Annotations live in `internal/registry/helpers-v1.json`, drift-checked
by `internal/registry/helpers_test.go` and
`capability/helper_effects_drift_test.go`. See the `helper_effects`
section in [`v0-to-v1-manifest.md`](v0-to-v1-manifest.md).

### Capability `origin` field on imported declarations

Cross-package builds now stamp `origin: "<import-alias>"` on
`Capability`, `Map`, and `TypeSchema` entries that came from an
imported package. The schema constant stays at `v1`; old readers ignore
the field. Worked example: `examples/imported-execcount/` and its
golden manifest at
`testdata/golden/examples/imported-execcount/prog.cap.json`.

### Package composition

A build may now span multiple `.hzn` files in one directory (same
`package` decl) and import sibling or vendored packages by
URL-shaped path (`import events "m31labs.dev/myorg/events"`,
resolved via `./vendor/<full-path>/`). No remote fetch, no
lockfile — purely compile-time-resolvable. References:
`examples/multifile-execcount/`, `examples/imported-execcount/`,
[`v0.2-package-composition.md`](v0.2-package-composition.md).

### Verifier-message catalog

`internal/registry/verifier-catalog-v1.json` maps common kernel
verifier diagnostics to stable `HZN31xx` codes with remediation
guidance, rendered by `hzn diagnose`. Ten seed entries
(`VC0001`–`VC0010`) plus a hand-crafted fixture corpus under
`testdata/verifier-fixtures/`. Loader: `internal/registry/verifier_catalog.go`.

### Map capacity-planning annotations

`@steady_state_entries(N)` and `@access_freq("low"|"medium"|"high")`
on map declarations surface as `steady_state_entries` / `access_freq`
manifest fields (both `omitempty`). See `examples/openwatch/` for a
program using these annotations.

### `hzn build` / `hzn workbench -compile` clang timeout

`-clang-timeout=<duration>` flag and `HZN_CLANG_TIMEOUT` env var
(default 30s). Implemented in `cmd/hzn/build.go` and `cmd/hzn/workbench.go`.

## Validate-layer changes that may newly flag previously-passing code

These Phase 1 (Track A: Soundness) changes are not breaking in the
schema sense, but they catch unsound patterns the v0.1 validator missed.
A program that compiled cleanly under v0.1 may now produce a typed
diagnostic. In every case the v0.1 behavior was unsound — the kernel
verifier would have rejected the produced object.

| Change | Newly fails | Code path |
|---|---|---|
| Phase 1 #1 alias graph | `y := x` copies of a ringbuf reservation / map lookup / packet header pointer that the v0.1 validator silently treated as independent now correctly propagate state. Programs that used `submit(y)` after `y := x; bpf.helper(x)` will now fire the appropriate state-machine diagnostic. | `validate/aliases.go`, state machines in `validate/{ringbuf,maps,packet}.go` |
| Phase 1 #2 multi-condition nil-check recognition | `if x != nil && y != nil { ... }` now correctly promotes BOTH operands to live in the then-arm. Programs that previously relied on this and had unsound paths in the other arms surface now. | `validate/ringbuf.go`, `validate/maps.go`, `validate/packet.go` |
| Phase 1 #5 loop-carry 2-iteration fixpoint | `submit(event)` inside a `for` loop without re-reserving on each iteration fires `HZN2102` (double-submit). v0.1 only modeled the first iteration. | state machines, loop-aware traversal |
| Phase 1 #3 regex-fallback removal | Programs whose IR build produced a function with zero typed statements used to fall back to a regex scan. The regex paths are gone; any such function now fails the validate-layer pass cleanly (and would have already been a parser/IR bug). | `validate/{ringbuf,loops,helpers}.go` |

## New diagnostic codes

Per-code phrasing lives in the per-area migration guides; this is the
range map.

| Range | Owner | Area | Reference |
|---|---|---|---|
| `HZN13xx` | Phase 1 | Type-checker relaxations for resource-typed helper params and related signature rules. | `types/checker.go` |
| `HZN15xx` | Phase 2 (spruce) | Package composition: import resolution, alias collisions, qualified-selector type errors, cross-package map/struct/capability collisions. See [`v0.2-package-composition.md`](v0.2-package-composition.md#new-diagnostics) for the per-code table. | `compiler/imports.go`, `types/checker.go`, `capability/aggregate.go`, `ir/qualified.go` |
| `HZN31xx` | Phase 2 (pine) | Verifier-message catalog. `HZN3100` is the generic fallback; `HZN3110`–`HZN3199` are catalog-classified entries. Each `VCxxxx` registry entry stamps a specific code. | `internal/registry/verifier_catalog.go`, `verifier/remap.go` |
| `HZN3302`/`HZN3303` | Phase 1 (cedar) | Manifest schema-version contract: `HZN3302` rejects unknown schemas; `HZN3303` warns on auto-migrated v0 manifests. | `capability/load.go` |
| Helper-effects validation | Phase 2 (oak) | `helper_effects` token-vocabulary validation and registry-coverage drift. No new HZN-coded user diagnostics in v0.2; failures surface through the drift test at build time. | `capability/helper_effects.go`, `internal/registry/helpers_test.go` |

## Documented limits

These are limits of the v0.2 implementation that users may hit. They
are not bugs; the migration story works around or accepts them.

- **`VC0001` remediation template renders `()` when no register capture.**
  The catalog template treats `{{.Captures.register}}` as optional but
  the literal `()` wrapper around it is unconditional. Cosmetic; the
  surrounding remediation text is still correct.
- **`HZN1564` and `HZN1565` are reused at two layers (v0.2 only).** In
  v0.2 they fire at both the manifest aggregator
  (`capability/aggregate.go`) and the IR merge (`ir/qualified.go`) with
  identical message templates, so downstream consumers need only one
  branch per concern. v0.3 splits the aggregator codes off to
  `HZN1566` / `HZN1567`; see
  [`v0.2-to-v0.3.md`](v0.2-to-v0.3.md) for the per-layer allocation.
- **`examples/eventbatch/` is not in the golden harness.** It builds
  and is referenced from the Makefile, but is not in the `examples`
  slice in `compiler/golden_examples_test.go`. The ringbuf-through-helper
  pattern is exercised by the example itself and by
  `validate/helper_effects.go` unit tests.
- **The verifier-message catalog ships with synthetic fixtures only.**
  Real-kernel fixture capture is gated on canned BTF-enabled qcow2
  images publishing at `M31-Labs/horizon-kernel-images`.
- **DeMorgan and mixed-op nil-check chains are not recognized.**
  `!(x == nil)` and `||`-disjunctions do not currently promote
  operands in the validate-layer nil-check recognition. `&&`-chains
  do (Phase 1 #2). Programs using the unrecognized forms remain
  conservatively flagged — the validator may flag a path it should
  know is safe; the inverse (accepting an unsafe path) does not occur.
- **`struct_ops` bindgen attach is stubbed.** The example
  (`examples/structopstcp/`) compiles and emits a manifest, but
  `bindgen/generate.go:emitStructOpsAttach` returns an error if
  invoked. A typed `AttachOnFn` binding helper for `struct_ops`
  programs is not yet implemented.
- **Helper-effect annotations are limited to compiler-known helpers.**
  Context accessors (`kprobe.arg*`), packet parsers
  (`xdp.Eth/IPv4/TCP/UDP`), endianness intrinsics, and `CONFIG_*`
  kernel-feature requirements are not annotated.
- **Interprocedural alias tracking does not follow struct fields.**
  Aliases captured into struct fields, or per-call-site path-sensitive
  helper-effect summaries, are not modeled.

## Links

- [`v0-to-v1-manifest.md`](v0-to-v1-manifest.md) — capability manifest
  v0 → v1, danger axes, attach surfaces, `helper_effects`, deprecation
  timeline.
- [`v0.2-package-composition.md`](v0.2-package-composition.md) —
  multi-file packages, cross-package imports, vendoring, aggregation
  rules, `HZN15xx` diagnostic catalog.
- [`../../CHANGELOG.md`](../../CHANGELOG.md) — the full `[Unreleased]`
  section enumerates every Phase 0/1/2 change with roadmap-issue
  attribution.
