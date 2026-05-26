<<<<<<< HEAD
# Vendored Horizon registries

This directory vendors canonical Horizon registry documents from
Hyphae. Each vendored JSON file MUST stay byte-identical to its
Hyphae original; drift checks fail CI when they diverge.

## Capability namespace registry

File: `capability-namespaces-v1.json`. Hyphae original:
=======
# Horizon vendored registries

This directory vendors the canonical Horizon registry documents. The
Hyphae originals live under
`~/.hyphae/spaces/m31labs-horizon/specs/`. Each vendored JSON file in
this directory MUST stay byte-identical to its Hyphae original. Drift
tests in this package skip defensively when the Hyphae file is absent
(e.g. CI runners without the workspace) but fail loudly when both files
are present and differ.
>>>>>>> 1dd5463 (add(internal/registry): Add helper side-effect registry loader and vendored spec)

Sibling-file pattern: each registry has its own loader Go file
(`registry.go` for capability namespaces, `helpers.go` for helper
side-effects). New registries land as additional sibling files; do not
extend existing loaders. This keeps parallel agent tracks from
rebase-colliding on a single loader file.

<<<<<<< HEAD
A drift check in `capability/registry_drift_test.go` enforces that
`ExpectedKernelCapabilityPrefix` in `capability/namespace.go` matches
this registry exactly. When the canonical Hyphae registry changes,
re-copy the file here and update `namespace.go` to match.

See spec.horizon-continuum-integration.v1 §A.3 for the registry's
contract role.

## Verifier-message catalog

File: `verifier-catalog-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/verifier-catalog-v1.json

Loaded by `verifier_catalog.go` (sibling file in this package) and
re-exported through `verifier/catalog.go`. A drift check in
`verifier_catalog_drift_test.go` enforces byte-identity with the
Hyphae original.

See spec.horizon.verifier-catalog.v1 for the catalog's schema and
the per-entry field reference.
=======
## Capability namespace registry

- Hyphae source: `~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json`
- Vendored: `capability-namespaces-v1.json`
- Loader: `registry.go` (exports `Load`, `MustLoad`, `Registry`, `Namespace`)
- Contract role: spec.horizon-continuum-integration.v1 §A.3
- Drift discipline: when the canonical Hyphae registry changes, re-copy
  the file here and update `capability/namespace.go`'s
  `ExpectedKernelCapabilityPrefix` to match.

## Helper side-effect registry

- Hyphae source: `~/.hyphae/spaces/m31labs-horizon/specs/helpers-v1.json`
- Vendored: `helpers-v1.json`
- Loader: `helpers.go` (exports `LoadHelpers`, `MustLoadHelpers`,
  `Helpers`, `HelpersRegistry`, `Helper`)
- Contract role: spec.horizon-continuum-integration.v1 §A.7 (planned);
  decision.horizon.0002-helper-side-effects-v1.
- Drift discipline: this registry pins one entry per compiler-known
  helper. A cross-package drift test in
  `capability/helper_effects_drift_test.go` enforces that every helper
  in `compilerHelperRequirements` and every method in `mapMethodHelper`
  has a registry entry. Adding a helper without an entry is a
  build-breaking error.
>>>>>>> 1dd5463 (add(internal/registry): Add helper side-effect registry loader and vendored spec)
