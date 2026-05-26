package registry

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestVerifierCatalogMatchesHyphaeSource asserts the embedded
// internal/registry/verifier-catalog-v1.json is byte-identical to the
// canonical Hyphae source at
// ~/.hyphae/spaces/m31labs-horizon/specs/verifier-catalog-v1.json.
//
// Mirrors the capability-namespace registry drift contract from
// spec.horizon-continuum-integration.v1 §A.3, applied to the
// verifier-message catalog defined in spec.horizon.verifier-catalog.v1.
//
// Skips when the Hyphae source is unreachable (no $HOME, or the file
// is not present — e.g., when running under CI in a fresh container).
// The drift contract is enforced for developers who have the Hyphae
// space checked out; CI without the Hyphae space falls back to the
// embedded-bytes-only contract proven by the loader tests.
func TestVerifierCatalogMatchesHyphaeSource(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory available: %v", err)
	}
	hyphaePath := filepath.Join(home, ".hyphae", "spaces", "m31labs-horizon", "specs", "verifier-catalog-v1.json")
	source, err := os.ReadFile(hyphaePath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("Hyphae source not found at %s; skipping drift check", hyphaePath)
		}
		t.Fatalf("read Hyphae source %s: %v", hyphaePath, err)
	}
	if !bytes.Equal(source, verifierCatalogJSON) {
		t.Fatalf("drift: internal/registry/verifier-catalog-v1.json (%d bytes) is not byte-identical to %s (%d bytes); re-copy the Hyphae source over the vendored file", len(verifierCatalogJSON), hyphaePath, len(source))
	}
}
