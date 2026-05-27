// Clang-message catalog re-exports. The catalog itself is vendored
// under internal/registry/clang-catalog-v1.json and loaded by
// internal/registry/clang_catalog.go (the embed lives next to the
// JSON file). This file re-exports the public surface so callers can
// write verifier.LoadClangCatalog / verifier.LookupClangCatalog
// without taking a direct dependency on internal/registry.
//
// Strict sibling of verifier/catalog.go (the verifier-message catalog
// re-export). The two catalogs are mutually exclusive by origin:
// callers gate on d.Kind == "clang_diagnostic" to choose which
// catalog to consult. See cmd/hzn/diagnose.go.
//
// See spec.horizon.clang-catalog.v1.

package verifier

import (
	"m31labs.dev/horizon/internal/registry"
)

// ClangCatalog is the parsed clang-message catalog. Re-export of
// registry.ClangCatalog so callers in this package and below stay
// inside the verifier/ namespace.
type ClangCatalog = registry.ClangCatalog

// ClangCatalogEntry is one row of the catalog. Re-export of
// registry.ClangCatalogEntry.
type ClangCatalogEntry = registry.ClangCatalogEntry

// ClangCatalogMatch is an entry's match block. Re-export of
// registry.ClangCatalogMatch.
type ClangCatalogMatch = registry.ClangCatalogMatch

// LoadClangCatalog parses, validates, and compiles the embedded
// catalog. Returns an error for any malformed shape.
func LoadClangCatalog() (ClangCatalog, error) {
	return registry.LoadClangCatalog()
}

// MustLoadClangCatalog is LoadClangCatalog that panics on error.
// Suitable for package-level initialization; the embedded JSON is
// build-time constant so a panic here is a build bug, not a runtime
// concern.
func MustLoadClangCatalog() ClangCatalog {
	return registry.MustLoadClangCatalog()
}

// LookupClangCatalog is a convenience that loads the catalog once per
// call and runs Lookup. Tests and one-off callers may prefer this; hot
// paths should call MustLoadClangCatalog at init and call
// (ClangCatalog).Lookup directly.
func LookupClangCatalog(message, raw string) (ClangCatalogEntry, map[string]string, bool) {
	return MustLoadClangCatalog().Lookup(message, raw)
}
