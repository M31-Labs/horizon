# Changelog

All notable changes to Horizon are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `HZN1564` (struct shape conflict) and `HZN1565` (capability schema conflict)
  now fire only at the IR merge layer (`ir.MergeWithDiagnostics`). The
  manifest-aggregation layer (`capability.AggregateManifests`) now emits the
  new codes `HZN1566` (map shape conflict, post-aggregation) and `HZN1567`
  (type schema conflict, post-aggregation). Distinct `Suggest` strings name
  the layer at which the conflict was detected so CI logs and downstream
  consumers no longer need to disambiguate by inspecting code. See
  `docs/migrations/v0.2-to-v0.3.md`. (roadmap: #9)
- Legacy `cmd/hzn/diagnose.go:verifierSuggestion` switch removed; remediation
  guidance now flows exclusively from the verifier catalog. Unrecognized
  verifier messages fall back to `HZN3100` with no `suggest`. (roadmap: #14)
- Unknown attach surfaces and unknown namespace/leaf combinations now fail at
  parse/type-check time via the canonical registry, rather than slipping through
  to emit-time `HZN3300`. The `recognizedCapabilityLeaf` hardcoded list and
  `ExpectedKernelCapabilityPrefix` switch are replaced by registry-driven lookups.
  (roadmap: #10)
- **Breaking:** Capability manifest schema bumped from `m31labs.dev/horizon/capability/v0` to `v1`. Danger is now an axis triple (`mode` × `scope` × `reversibility`) rather than a flat enum. v0 manifests remain loadable via `capability.LoadManifest()` (auto-migrated in memory, emits `HZN3303` deprecation warning). New manifest emission always uses v1. See `docs/migrations/v0-to-v1-manifest.md`. (roadmap: #6, #7)
- `ir.Program` no longer carries a partially-populated `SourceMap` field. Source maps are owned end-to-end by `emitc.Output`. No CLI / artifact change. (roadmap: #12)
- Validators (`validate/`) now share a single IR traversal via `validate.Collect`. Each rule consumes pre-collected sites rather than re-walking. No diagnostic-output change; contract-tested against every example. `StackLocalSite` carries the inferred aggregate `Type` and covers literal struct/array declarations alongside short_vars whose RHS resolves to an aggregate by value (e.g. `event := makeEvent()`); `validate/stack.go`'s byte-accounting walker consumes the site index for type lookup instead of re-running expression-type inference. (roadmap: #4)
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
  DeMorgan equivalences (`!(x == nil)`) and mixed-op chains are not
  recognized in v0.2. (roadmap: #2)
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
- User-defined helper functions may now accept nullable resource handles
  (ringbuf reservations, map lookup pointers, packet headers) as
  parameters. HZN1319 in `types/checker.go` no longer rejects these
  pointer-typed helper parameters; the new `ir.Param.Resource` bit
  marks them at IR-build time. Validate-layer state machines
  (ringbuf, maps, packet) now propagate helper effects across user
  helper calls via `validate/helper_effects.go`: callers observe the
  helper's verdict (`Consumes`, `Preserves`, `Mixed`, `Unknown`) and
  transition the caller-side resource state accordingly, replacing
  the previous unconditional `escaped` marking. Recursion is bounded
  at depth 8 (returns `Unknown` beyond, preserving soundness). HZN1447
  continues to fire for non-helper-call alias forms. New `eventbatch`
  example exercises the ringbuf-through-helper pattern end-to-end.
  (roadmap: #13)

### Added
- Helper-effect annotations extended to cover context accessors
  (`kprobe.arg1..arg5`, `kretprobe.ret`,
  `cgroup.{family,sock_type,protocol,dst_port,dst_ip4,src_ip4,ip4}`),
  packet parsers (`xdp.{eth,ipv4,tcp,udp,ntohs}`), and endianness
  intrinsics (`bpf.{htons,htonl,ntohs,ntohl}`). Registry
  (`internal/registry/helpers-v1.json`) grew from 12 to 34 entries; the
  closed observation-token vocabulary gained three new dotted roots —
  `kernel.syscall.*`, `kernel.socket.*`, `kernel.network.packet.*` —
  mirrored in both `internal/registry/helpers.go::allowedHelperObserveTokens`
  and `capability/validate.go::observeVocabulary` and pinned by a new
  cross-package drift test (`capability/vocabulary_drift_test.go`).
  Pure-compute and pure-construction helpers (endianness ops,
  `cgroup.ip4`, `xdp.ntohs`) carry explicit empty `observes` / `mutates`
  arrays as a positive "I observe nothing" assertion. Goldens for
  `openwatch`, `cgroupconnect`, and `xdpdrop` regenerated to surface
  the new `helper_effects` entries. (roadmap: #10)
- Verifier-message catalog (`internal/registry/verifier-catalog-v1.json`)
  maps common verifier diagnostics to stable `HZN31xx` codes with
  remediation guidance. `hzn diagnose` now sets a per-entry code and
  renders the catalog's remediation as the diagnostic's `suggest` text.
  Ships with 10 seed entries (`VC0001`–`VC0010`) and a hand-crafted
  fixture corpus under `testdata/verifier-fixtures/`. A real-kernel
  fixture corpus is gated on canned BTF-enabled qcow2 images publishing
  at `M31-Labs/horizon-kernel-images`. (roadmap: #14)
- `validate/helpers.go` recognizes the seven new attach surfaces (uprobe, uretprobe, fentry, fexit, raw_tp, sockops, struct_ops) as known program kinds; uprobe/uretprobe/fentry/fexit/raw_tp count as tracing programs so the existing `bpf.current_pid()`/`bpf.ktime_get_ns()` style helpers are now available to those programs. Resolves the Phase 1 cross-track coordination gap that had the new surfaces' examples hardcoding `event.pid = 0`. (Phase 1 integration, follows roadmap #9 + #4)
- Map declarations may now carry `@steady_state_entries(N)` (positive integer ≤ `max_entries`) and `@access_freq("low"|"medium"|"high")` annotations. Both fields surface in manifest v1 for capacity planning. (roadmap: #22)
- Seven new attach surfaces recognized end-to-end: uprobe, uretprobe, fentry, fexit, raw_tp, sockops, struct_ops. Each ships with at least one example, registry entries, manifest emission, and (where the attach path is tractable) a typed `Attach<Fn>` binding helper. struct_ops attach helpers are stubbed pending a follow-up. (roadmap: #9)
- Capability danger now carries orthogonal axes (`mode` × `scope` × `reversibility`) alongside the legacy flat string. `mode` ∈ `{observe, mutate, control}`, `scope` ∈ `{event, process, network, filesystem, system}`, `reversibility` ∈ `{none, restart, persistent}`. Legacy flat danger words map to axes via a deterministic migration table. The `.hzn` declaration site accepts both flat words (`"observe"`) and explicit triples (`"control,network,restart"`). Manifest schema v1 (roadmap: #6) will surface the axes in the emitted artifact. (roadmap: #7)
- `hzn build` and `hzn workbench -compile` now accept `-clang-timeout=<duration>` and read `HZN_CLANG_TIMEOUT` from the environment. Default remains 30s. (roadmap: #11)
- Golden-snapshot tests for every example's full `hzn workbench` output (C + manifest + bindings + diagnostics + report). Regenerate with `make golden-update`. (roadmap: #16)
- `parser.FuzzParse` Go-native fuzz target, seeded from `examples/`. Runs 60s per PR in CI; longer fuzz budgets available out-of-band. Contract: parser never panics on any input. (roadmap: #17)
- Kernel-version test matrix scaffolding (`.github/workflows/kernel-matrix.yml`, `scripts/kernel-matrix/`, `make kernel-smoke`): structural artifacts only. Trigger is `workflow_dispatch` only until canned BTF-enabled qcow2 images publish at `M31-Labs/horizon-kernel-images`. Boot/smoke scripts are stubbed with EX_CONFIG (exit 78) until images land. Once images exist, a follow-up will add auto-triggers (`pull_request`/`push`) and fill in the boot bodies. Per spec §4.2.1, 6.1 + 6.6 are required for Phase 0 exit; 5.10 / 5.15 are best-effort. (roadmap: #19)
- Behavior tests for generated bindings: `LoadObjects` survives nil-section/empty-map cases without panic, and ringbuf readers unwind cleanly on context cancellation. (roadmap: #18)
- Helper side-effect modeling: each `Capability` in the manifest now carries an additive `helper_effects` array describing what observations, mutations, kernel requirements, and resource verbs each program's helper calls represent. Annotations live in the vendored `internal/registry/helpers-v1.json` registry, drift-checked against the compiler-known helper inventory. Downstream consumers (Continuum) can vendor the same registry. See `docs/migrations/v0-to-v1-manifest.md` §helper_effects. (roadmap: #8)
- Multi-file packages: a Horizon source tree may now span multiple `.hzn`
  files that share a single `package` declaration. The compiler aggregates
  every file under the build root into one logical package via
  `ast.GroupByPackage`, type-checks the union (cross-file duplicate
  identifiers fire `HZN1551` with the prior file path attached), and
  lowers the merged AST through a single IR build. Examples ship as
  `examples/multifile-execcount/` (root package split across files) and
  `examples/imported-execcount/` (root + vendored dependency). (roadmap: #20)
- Cross-package imports: `import alias "path/to/pkg"` resolves relative to
  the build root, walks vendored sources under `vendor/`, and routes
  qualified references (`alias.Type`, `alias.helper()`, `@capability(alias.Name)`)
  through the type checker, IR builder, and capability aggregator. Each
  contributing package is lowered independently; the aggregator merges
  per-package manifests, stamping `Origin` on `Capability`, `Map`, and
  `TypeSchema` so downstream consumers can trace which import each artifact
  came from. Collisions across packages (duplicate map names, capability
  names, struct names) surface as `HZN15xx` diagnostics through
  `hzn check`. Cross-package builtin aliases (e.g. `import bee
  "m31labs.dev/horizon/runtime/kernel"`) route to the compiler namespace.
  Builds with only-unreachable imported entrypoints emit advisory
  `HZN1561`. Parser fuzz seeds and an `examples/imported-execcount/`
  vendored fixture exercise the end-to-end flow. Remote import fetching,
  package versioning, re-exports, and per-package published manifests
  are explicitly out of scope. See `docs/migrations/v0.2-package-composition.md`.
  (roadmap: #21)

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
