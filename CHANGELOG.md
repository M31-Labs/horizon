# Changelog

All notable changes to Horizon are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Unknown attach surfaces and unknown namespace/leaf combinations now fail at
  parse/type-check time via the canonical registry, rather than slipping through
  to emit-time `HZN3300`. The `recognizedCapabilityLeaf` hardcoded list and
  `ExpectedKernelCapabilityPrefix` switch are replaced by registry-driven lookups.
  (roadmap: #10)
- **Breaking:** Capability manifest schema bumped from `m31labs.dev/horizon/capability/v0` to `v1`. Danger is now an axis triple (`mode` × `scope` × `reversibility`) rather than a flat enum. v0 manifests remain loadable via `capability.LoadManifest()` (auto-migrated in memory) through v0.2.x; v0 loader will be removed in v0.3. New manifest emission always uses v1. See `docs/migrations/v0-to-v1-manifest.md`. (roadmap: #6, #7)
- `ir.Program` no longer carries a partially-populated `SourceMap` field. Source maps are owned end-to-end by `emitc.Output`. No CLI / artifact change. (roadmap: #12)
- Validators (`validate/`) now share a single IR traversal via `validate.Collect`. Each rule consumes pre-collected sites rather than re-walking. No diagnostic-output change; contract-tested against every example. Note: `StackLocalSite` detection is currently narrower than the legacy `stack.go` inference (literal struct/array declarations only); `stack.go`'s inferred-type pass remains for the broader case. Future work may extend `StackLocalSite` with inferred type to fully unify. (roadmap: #4)
- Validate-layer state machines (ringbuf, maps, packet) now track
  intra-function aliasing via `y := x` copies and mark resources as
  `escaped` when passed as a call argument. Cross-function (interprocedural)
  alias tracking remains deferred to Phase 2 #13 (`maple`). HZN1447 in
  `types/` still rejects user-written aliases at source level; the
  validate-layer machinery exists so that when #13 relaxes HZN1447 for
  helper-arg passes, the state machine is ready. (roadmap: #1)
- Validate-layer nil-check recognition (ringbuf, maps, packet) now
  handles `&&`-chained comparisons: `if x != nil && y != nil { ... }`
  promotes BOTH `x` and `y` to live in the then-arm. `||` disjunctions
  remain conservatively NOT promoted (only one disjunct may hold).
  DeMorgan equivalences (`!(x == nil)`) and mixed-op chains deferred
  to v0.3. (roadmap: #2)
- Validate-layer state machines (ringbuf, maps, packet) now model
  resource state across `for` loop iterations via a bounded 2-iteration
  fixpoint. Patterns that would change state between iterations — e.g.,
  `submit(event)` inside a loop without re-reserving — now correctly
  fire HZN2102 (double-submit). Sound patterns (reserve→nil-check→submit
  per iteration) continue to pass. Range-over and `for {}` are not
  specially modeled (HZN2200 still rejects `for {}`; range-over not in
  v0.2 grammar). (roadmap: #5)
- Validate-layer regex fallbacks deleted. `validate/{ringbuf,loops,helpers}.go`
  no longer contain `bodyLines + regex` paths for functions without typed
  statements. With Phase 1 #1/#2/#5 landed, the typed-IR state machines
  cover every supported program shape; the regex paths were masking
  coverage gaps. Removal exposes any IR-build path that produces a
  function with no typed statements as a parser/IR bug (none remain in
  the test fixtures or examples). (roadmap: #3)

### Added
- `validate/helpers.go` recognizes the seven new attach surfaces (uprobe, uretprobe, fentry, fexit, raw_tp, sockops, struct_ops) as known program kinds; uprobe/uretprobe/fentry/fexit/raw_tp count as tracing programs so the existing `bpf.current_pid()`/`bpf.ktime_get_ns()` style helpers are now available to those programs. Resolves the Phase 1 cross-track coordination gap that had the new surfaces' examples hardcoding `event.pid = 0`. (Phase 1 integration, follows roadmap #9 + #4)
- Map declarations may now carry `@steady_state_entries(N)` (positive integer ≤ `max_entries`) and `@access_freq("low"|"medium"|"high")` annotations. Both fields surface in manifest v1 for capacity planning. (roadmap: #22)
- Seven new attach surfaces recognized end-to-end: uprobe, uretprobe, fentry, fexit, raw_tp, sockops, struct_ops. Each ships with at least one example, registry entries, manifest emission, and (where the attach path is tractable) a typed `Attach<Fn>` binding helper. struct_ops attach helpers are stubbed pending a follow-up. (roadmap: #9)
- Capability danger now carries orthogonal axes (`mode` × `scope` × `reversibility`) alongside the legacy flat string. `mode` ∈ `{observe, mutate, control}`, `scope` ∈ `{event, process, network, filesystem, system}`, `reversibility` ∈ `{none, restart, persistent}`. Legacy flat danger words map to axes via a deterministic migration table. The `.hzn` declaration site accepts both flat words (`"observe"`) and explicit triples (`"control,network,restart"`). Manifest schema v1 (roadmap: #6) will surface the axes in the emitted artifact. (roadmap: #7)
- `hzn build` and `hzn workbench -compile` now accept `-clang-timeout=<duration>` and read `HZN_CLANG_TIMEOUT` from the environment. Default remains 30s. (roadmap: #11)
- Golden-snapshot tests for every example's full `hzn workbench` output (C + manifest + bindings + diagnostics + report). Regenerate with `make golden-update`. (roadmap: #16)
- `parser.FuzzParse` Go-native fuzz target, seeded from `examples/`. Runs 60s per PR in CI; longer fuzz budgets available out-of-band. Contract: parser never panics on any input. (roadmap: #17)
- Kernel-version test matrix scaffolding (`.github/workflows/kernel-matrix.yml`, `scripts/kernel-matrix/`, `make kernel-smoke`): structural artifacts only. Trigger is `workflow_dispatch` only until canned BTF-enabled qcow2 images publish at `M31-Labs/horizon-kernel-images`. Boot/smoke scripts are stubbed with EX_CONFIG (exit 78) until images land. Once images exist, a follow-up will add auto-triggers (`pull_request`/`push`) and fill in the boot bodies. Per spec §4.2.1, 6.1 + 6.6 are required for Phase 0 exit; 5.10 / 5.15 are best-effort. (roadmap: #19)
- Behavior tests for generated bindings: `LoadObjects` survives nil-section/empty-map cases without panic, and ringbuf readers unwind cleanly on context cancellation. (roadmap: #18)

## [v0.1.2] — 2026-05-25

### Added
- Canonical capability-namespace registry (`internal/registry/`)
  vendored from `~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json`.
  Identifies which kernel attach surfaces map to which `kernel.*`
  namespace prefixes, and which leaf words are allowed per
  (namespace, attach surface). Both Horizon and Continuum vendor the
  same registry as the single source of truth.
- LSM `bprm_check_security` and `task_kill` attach strings now
  recognized by `ExpectedKernelCapabilityPrefix` (introduced by the
  v0.1.0 Continuum dogfood pass).
- Drift test (`capability/registry_drift_test.go`) pins
  `ExpectedKernelCapabilityPrefix` against the registry — adding a
  switch arm without a matching registry entry (or vice versa) fails
  CI.
- Contract test (`compiler/registry_contract_test.go`) walks every
  example, compiles it, and validates the emitted manifest's
  capabilities against the registry.

### Reference
- spec.horizon-continuum-integration.v1 §A.3 + §A.4 (emit side).

## [v0.1.1] — 2026-05-25

### Fixed
- **HZN1326 (security):** capability names in the reserved `kernel.*`
  namespace must end in a recognized leaf word (`observe`, `mutate`,
  `drop`, `block`, `privileged`, `deny`, or `allow`). Previously, names
  like `kernel.network.connect.grant` silently passed validation with
  arbitrary danger levels, producing manifests whose names didn't match
  their semantics. Closes the false-acceptance hole reported in the
  Horizon × Continuum dogfood pass on 2026-05-25. See
  spec.horizon-continuum-integration.v1 §A.1.

### Changed
- `examples/execcount` capability renamed from
  `kernel.process.exec.count` to `kernel.process.exec.count.observe`
  to conform to the new leaf rule. No userspace API change. README
  sample code blocks updated to match.

## [v0.1.0] — 2026-05-25

### Added
- First tagged release of Horizon. Pre-alpha graduated to the v0.x line.
- `m31labs.dev/horizon` vanity import. `go install m31labs.dev/horizon/cmd/hzn@v0.1.0` works.
- Release workflow on tag push. Each tag produces a GitHub Release with notes drawn from this file.
- CHANGELOG.md.
- `capabilities` CLI subcommand documented in the README Commands catalog with a happy-path test.
- README sections: "What Horizon solves," "The Workbench," "A program end-to-end," "What Horizon won't do," "Capability manifests."
- Test fixture for ringbuf reservations across `switch` branches, locking the multi-branch state-merge analysis for HZN2104 detection.

### Changed
- README rewritten around author pains and the workbench as the flagship authoring path.
- Safety Model regrouped under themes (resource typing, type/width discipline, capability discipline, verifier-aware constraints, generated-artifact discipline).
- Status section now points at this CHANGELOG.

### Fixed
- (none yet)
