# Changelog

All notable changes to Horizon are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] — TBD

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
