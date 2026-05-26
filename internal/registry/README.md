# Vendored Horizon registries

This directory vendors canonical Horizon registry documents from
Hyphae. Each vendored JSON file MUST stay byte-identical to its
Hyphae original; drift checks fail CI when they diverge.

## Capability namespace registry

File: `capability-namespaces-v1.json`. Hyphae original:

    ~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json

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
