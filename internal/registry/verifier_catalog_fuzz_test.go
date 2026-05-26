// Fuzz seeds for the verifier-message catalog loader and lookup.
//
// The catalog parses external JSON and compiles caller-supplied regex
// patterns; both are fuzz-attractive surfaces. Mirrors Phase 0 #17's
// parser/fuzz_test.go convention: panic-only contract, errors are
// fine, match results unconstrained.
//
// See roadmap #14 and the v0.2 Phase 2 pine plan (Task 5.5).

package registry

import (
	"testing"
)

// FuzzVerifierCatalogLoad fuzzes the embed-equivalent loader entry point
// LoadVerifierCatalogBytes. The seed corpus exercises the full embedded
// catalog plus deliberately truncated and malformed inputs near common
// JSON / regex boundaries. The body asserts the loader never panics;
// returning an error is fine.
func FuzzVerifierCatalogLoad(f *testing.F) {
	// Seed 1: the embedded catalog itself (must parse).
	f.Add(verifierCatalogJSON)

	// Seed 2: truncations at common boundaries.
	if n := len(verifierCatalogJSON); n > 0 {
		head := func(k int) []byte {
			if k > n {
				k = n
			}
			out := make([]byte, k)
			copy(out, verifierCatalogJSON[:k])
			return out
		}
		f.Add(head(100))
		f.Add(head(500))
		f.Add(head(n / 2))
	}

	// Seed 3: empty / minimal-shape malformed inputs.
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"m31labs.dev/horizon/verifier-catalog/v1","version":"1","entries":[]}`))

	// Seed 4: catalog with a malformed regex pattern (compile path).
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/verifier-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "VC9999",
      "summary": "fuzz seed",
      "match": {"kind": "regex", "patterns": ["[unterminated"]},
      "hzn_code": "HZN3199",
      "remediation": "n/a",
      "introduced": "v0.2.0"
    }
  ]
}`))

	// Seed 5: catalog with a malformed capture fragment.
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/verifier-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "VC9998",
      "summary": "fuzz seed",
      "match": {
        "kind": "regex",
        "patterns": ["fuzz"],
        "captures": {"bad": "(unbalanced"}
      },
      "hzn_code": "HZN3199",
      "remediation": "n/a",
      "introduced": "v0.2.0"
    }
  ]
}`))

	// Seed 6: schema mismatch.
	f.Add([]byte(`{"schema":"unknown/schema/v999","version":"1","entries":[]}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Contract: no panic. Errors are fine; any returned catalog is
		// not inspected — the only failure mode this fuzz cares about is
		// a panic in the loader (parse, validate, regex compile).
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("LoadVerifierCatalogBytes panicked on input (len=%d): %v", len(raw), r)
			}
		}()
		_, _ = LoadVerifierCatalogBytes(raw)
	})
}

// FuzzVerifierCatalogLookup fuzzes Catalog.Lookup against arbitrary
// strings. The seed corpus draws from verifier/log_test.go's known
// verifier log lines plus a few clang-shaped and pathological inputs.
// The body asserts no panic; match results are unconstrained.
func FuzzVerifierCatalogLookup(f *testing.F) {
	// Seeds: verifier log lines transcribed from verifier/log_test.go
	// (TestParseLogIgnoresVerifierProcessedSummary,
	// TestParseLogPreservesRecentVerifierContext) plus the message-only
	// shapes the catalog cares about.
	seeds := []string{
		"0: R1=ctx() R10=fp0",
		"; bad_access();",
		"invalid mem access 'scalar'",
		"R2 invalid mem access 'scalar'",
		"R3 invalid mem access 'inv'",
		"Unreleased reference id=2",
		"back-edge from insn 42 to 12",
		"BPF program is too large. Processed 1000001 insn",
		"unknown func bpf_probe_read_user",
		"R0 !read_ok",
		"combined stack size of 3 calls is 600. Too large",
		"misaligned stack access",
		"processed 12 insns (limit 1000000) max_states_per_insn 0",
		"; event->pid = bpf.current_pid();",
		"2: (7b) *(u64 *)(r10 -8) = r1",
		"completely unrelated text not in the catalog",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	catalog, err := LoadVerifierCatalog()
	if err != nil {
		f.Fatalf("LoadVerifierCatalog: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Catalog.Lookup panicked on input %q: %v", input, r)
			}
		}()
		_, _, _ = catalog.Lookup(input, "")
	})
}
