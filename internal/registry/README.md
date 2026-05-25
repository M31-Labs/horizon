# Capability namespace registry (vendored)

This directory vendors the canonical Horizon capability-namespace
registry document. The Hyphae original lives at:

    ~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json

This vendored copy MUST stay byte-identical to the Hyphae original.
A drift check in `capability/registry_drift_test.go` enforces that
`ExpectedKernelCapabilityPrefix` in `capability/namespace.go` matches
this registry exactly. When the canonical Hyphae registry changes,
re-copy the file here and update `namespace.go` to match.

See spec.horizon-continuum-integration.v1 §A.3 for the registry's
contract role.
