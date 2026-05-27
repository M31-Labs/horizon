# Vendored Horizon registries

This directory vendors canonical Horizon registry documents from
Hyphae. Each vendored JSON file MUST stay byte-identical to its
Hyphae original; drift checks fail CI when they diverge. Drift tests
skip defensively when the Hyphae file is absent (e.g. CI runners
without the workspace) but fail loudly when both files are present
and differ.

Sibling-file pattern: each registry has its own loader Go file
(`registry.go` for capability namespaces, `helpers.go` for helper
side-effects, `verifier_catalog.go` for the verifier-message catalog,
`clang_catalog.go` for the clang-message catalog). New registries land
as additional sibling files; do not extend existing loaders. This keeps
parallel agent tracks from rebase-colliding on a single loader file.

## Capability namespace registry

File: `capability-namespaces-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json

A drift check in `capability/registry_drift_test.go` enforces that
`ExpectedKernelCapabilityPrefix` in `capability/namespace.go` matches
this registry exactly. When the canonical Hyphae registry changes,
re-copy the file here and update `namespace.go` to match.

See spec.horizon-continuum-integration.v1 §A.3 for the registry's
contract role.

## Helper side-effect registry

File: `helpers-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/helpers-v1.json

Loaded by `helpers.go` (sibling file in this package). Pins one entry
per compiler-known helper. A cross-package drift test in
`capability/helper_effects_drift_test.go` enforces that every helper
in `compilerHelperRequirements` and every method in `mapMethodHelper`
has a registry entry. Adding a helper without an entry is a
build-breaking error.

See spec.horizon-continuum-integration.v1 §A.7 and
decision.horizon.0002-helper-side-effects-v1 for the contract.

## Verifier-message catalog

File: `verifier-catalog-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/verifier-catalog-v1.json

Loaded by `verifier_catalog.go` (sibling file in this package) and
re-exported through `verifier/catalog.go`. A drift check in
`verifier_catalog_drift_test.go` enforces byte-identity with the
Hyphae original.

See spec.horizon.verifier-catalog.v1 for the catalog's schema and
the per-entry field reference.

## Clang-message catalog

File: `clang-catalog-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/clang-catalog-v1.json

Loaded by `clang_catalog.go` (sibling file in this package) and
re-exported through `verifier/clang_catalog.go`. A drift check in
`clang_catalog_drift_test.go` enforces byte-identity with the Hyphae
original.

Strict sibling of the verifier-message catalog: same regex-with-named-
captures shape, same first-match-wins lookup, same drift / fuzz
contract. Codes live in the `HZN34xx` range (`HZN3400` = no-match
sentinel; `HZN3410`–`HZN3499` = classified entries). Catalog ids use
the `CC` prefix (parallel to verifier's `VC`). Mutually exclusive with
the verifier catalog by origin: callers gate on
`d.Kind == "clang_diagnostic"` to pick which catalog to consult.

See spec.horizon.clang-catalog.v1 and
decision.horizon.0005-clang-diagnostic-catalog for the contract.
