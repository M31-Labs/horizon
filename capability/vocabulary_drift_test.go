package capability

import (
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/internal/registry"
)

// TestObserveVocabularyMatchesRegistryAllowedTokens asserts that every
// dotted observe / mutate token actually emitted by a registry helper
// entry is recognized by capability/validate.go::observeVocabulary. The
// two sets are intentionally duplicated:
//
//   - internal/registry.allowedHelperObserveTokens is the source-of-truth
//     vocabulary the registry loader enforces against the vendored JSON.
//   - capability.observeVocabulary is the *manifest-side* vocabulary the
//     validator enforces against emitted Capability.HelperEffects values,
//     including manifests hand-crafted outside the emit pipeline that
//     never visited the registry.
//
// The validator MAY have extras (for hand-crafted manifests carrying
// tokens not in the registry); the registry MUST NOT carry tokens the
// validator doesn't understand. This test asserts the latter direction:
// the validator vocabulary is a superset of the set of tokens emitted by
// registry helper entries (excluding the map: / ringbuf: resource
// tokens, which carry the "$" placeholder in the registry and are
// validated by a separate pattern).
//
// Skipping a token from the validator vocabulary while adding it to the
// registry would let an emitted manifest carry a token the validator
// would later reject — a silent drift bug this test catches.
func TestObserveVocabularyMatchesRegistryAllowedTokens(t *testing.T) {
	registryEmittedTokens := collectRegistryEmittedObserveTokens()

	var missing []string
	for _, tok := range registryEmittedTokens {
		if observeVocabulary[tok] {
			continue
		}
		// Resource tokens (map:$ / ringbuf:$) are not in observeVocabulary
		// by design — they pass through the helperEffectResourceTokenPattern
		// path after substitution. Skip them here.
		if strings.HasPrefix(tok, "map:") || strings.HasPrefix(tok, "ringbuf:") {
			continue
		}
		missing = append(missing, tok)
	}

	if len(missing) > 0 {
		t.Fatalf("registry emits %d token(s) the validator's observeVocabulary does not recognize: %v\nadd them to capability/validate.go::observeVocabulary in lockstep with internal/registry/helpers.go::allowedHelperObserveTokens",
			len(missing), missing)
	}
}

// collectRegistryEmittedObserveTokens returns the sorted, deduplicated
// set of every observe / mutate token any registry helper entry carries.
// Used by the cross-vocabulary drift test to verify the manifest-side
// validator vocabulary is a superset of what the registry actually
// emits.
func collectRegistryEmittedObserveTokens() []string {
	r := registry.MustLoadHelpers()
	seen := map[string]bool{}
	for _, h := range r.Helpers {
		for _, tok := range h.Observes {
			seen[tok] = true
		}
		for _, tok := range h.Mutates {
			seen[tok] = true
		}
	}
	out := make([]string, 0, len(seen))
	for tok := range seen {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}
