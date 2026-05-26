// Verifier-message catalog re-exports. The catalog itself is vendored
// under internal/registry/verifier-catalog-v1.json and loaded by
// internal/registry/verifier_catalog.go (the embed lives next to the
// JSON file). This file re-exports the public surface so callers can
// write verifier.LoadCatalog / verifier.LookupCatalog without taking
// a direct dependency on internal/registry.
//
// See spec.horizon.verifier-catalog.v1.

package verifier

import (
	"m31labs.dev/horizon/internal/registry"
)

// Catalog is the parsed verifier-message catalog. Re-export of
// registry.VerifierCatalog so callers in this package and below stay
// inside the verifier/ namespace.
type Catalog = registry.VerifierCatalog

// CatalogEntry is one row of the catalog. Re-export of
// registry.VerifierCatalogEntry.
type CatalogEntry = registry.VerifierCatalogEntry

// CatalogMatch is an entry's match block. Re-export of
// registry.VerifierCatalogMatch.
type CatalogMatch = registry.VerifierCatalogMatch

// LoadCatalog parses, validates, and compiles the embedded catalog.
// Returns an error for any malformed shape.
func LoadCatalog() (Catalog, error) {
	return registry.LoadVerifierCatalog()
}

// MustLoadCatalog is LoadCatalog that panics on error. Suitable for
// package-level initialization; the embedded JSON is build-time
// constant so a panic here is a build bug, not a runtime concern.
func MustLoadCatalog() Catalog {
	return registry.MustLoadVerifierCatalog()
}

// LookupCatalog is a convenience that loads the catalog once per call
// and runs Lookup. Tests and one-off callers may prefer this; hot paths
// should call MustLoadCatalog at init and call (Catalog).Lookup
// directly.
func LookupCatalog(message, raw string) (CatalogEntry, map[string]string, bool) {
	return MustLoadCatalog().Lookup(message, raw)
}
