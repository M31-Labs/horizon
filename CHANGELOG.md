# Changelog

All notable changes to Horizon are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
