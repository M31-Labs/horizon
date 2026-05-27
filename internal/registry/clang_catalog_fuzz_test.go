// Fuzz seeds for the clang-message catalog loader and lookup.
//
// Strict sibling of verifier_catalog_fuzz_test.go. The catalog parses
// external JSON and compiles caller-supplied regex patterns; both are
// fuzz-attractive surfaces. Mirrors the panic-only contract from the
// verifier-catalog fuzz: errors are fine, match results unconstrained.
//
// See roadmap #13 and the v0.3 Phase 1 cedar plan (Task 7.8).

package registry

import (
	"testing"
)

// FuzzClangCatalogLoad fuzzes the embed-equivalent loader entry point
// LoadClangCatalogBytes. The seed corpus exercises the full embedded
// catalog plus deliberately truncated and malformed inputs near common
// JSON / regex boundaries. The body asserts the loader never panics;
// returning an error is fine.
func FuzzClangCatalogLoad(f *testing.F) {
	// Seed 1: the embedded catalog itself (must parse).
	f.Add(clangCatalogJSON)

	// Seed 2: truncations at common boundaries.
	if n := len(clangCatalogJSON); n > 0 {
		head := func(k int) []byte {
			if k > n {
				k = n
			}
			out := make([]byte, k)
			copy(out, clangCatalogJSON[:k])
			return out
		}
		f.Add(head(100))
		f.Add(head(500))
		f.Add(head(n / 2))
	}

	// Seed 3: empty / minimal-shape malformed inputs.
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"m31labs.dev/horizon/clang-catalog/v1","version":"1","entries":[]}`))

	// Seed 4: catalog with a malformed regex pattern (compile path).
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/clang-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "CC9999",
      "summary": "fuzz seed",
      "match": {"kind": "regex", "patterns": ["[unterminated"]},
      "hzn_code": "HZN3499",
      "remediation": "n/a",
      "introduced": "v0.3.0"
    }
  ]
}`))

	// Seed 5: catalog with a malformed capture fragment.
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/clang-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "CC9998",
      "summary": "fuzz seed",
      "match": {
        "kind": "regex",
        "patterns": ["fuzz"],
        "captures": {"bad": "(unbalanced"}
      },
      "hzn_code": "HZN3499",
      "remediation": "n/a",
      "introduced": "v0.3.0"
    }
  ]
}`))

	// Seed 6: schema mismatch.
	f.Add([]byte(`{"schema":"unknown/schema/v999","version":"1","entries":[]}`))

	// Seed 7: out-of-range HZN code (validator must reject, not panic).
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/clang-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "CC9997",
      "summary": "fuzz seed",
      "match": {"kind": "regex", "patterns": ["fuzz"]},
      "hzn_code": "HZN3100",
      "remediation": "n/a",
      "introduced": "v0.3.0"
    }
  ]
}`))

	// Seed 8: wrong prefix on id (validator must reject).
	f.Add([]byte(`{
  "schema": "m31labs.dev/horizon/clang-catalog/v1",
  "version": "1",
  "entries": [
    {
      "id": "VC0001",
      "summary": "fuzz seed",
      "match": {"kind": "regex", "patterns": ["fuzz"]},
      "hzn_code": "HZN3499",
      "remediation": "n/a",
      "introduced": "v0.3.0"
    }
  ]
}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Contract: no panic. Errors are fine; any returned catalog is
		// not inspected — the only failure mode this fuzz cares about is
		// a panic in the loader (parse, validate, regex compile).
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("LoadClangCatalogBytes panicked on input (len=%d): %v", len(raw), r)
			}
		}()
		_, _ = LoadClangCatalogBytes(raw)
	})
}

// FuzzClangCatalogLookup fuzzes ClangCatalog.Lookup against arbitrary
// strings. The seed corpus draws from representative clang stderr
// shapes (one per CC entry plus a few pathological inputs). The body
// asserts no panic; match results are unconstrained.
func FuzzClangCatalogLookup(f *testing.F) {
	// Seeds: representative clang stderr lines covering each CC entry
	// in the v1 catalog, plus pathological inputs.
	seeds := []string{
		"error: use of undeclared identifier 'bpf_get_current_pid_tgid'",
		"error: use of undeclared identifier 'bpf_probe_read_user_str'",
		"error: use of undeclared identifier 'helper_function'",
		"error: use of undeclared identifier 'foo'",
		"error: implicit declaration of function 'bpf_printk' is invalid in C99",
		"error: implicit declaration of function 'do_something'",
		"error: unknown type name 'task_struct'",
		"error: unknown type name 'struct_sock'",
		"error: expected ')'",
		"error: expected ';'",
		"error: expected expression",
		"error: expected '}'",
		"error: expected identifier or '('",
		"error: incompatible pointer types passing 'struct xdp_md *'",
		"error: incompatible integer types",
		"error: incompatible pointer to integer conversion",
		"error: incompatible integer to pointer conversion",
		"warning: some clang warning that should not match",
		"completely unrelated text that no catalog entry matches",
		// Verifier-shaped inputs (should not incidentally match clang
		// patterns; tests no-cross-vocabulary panic).
		"0: R1=ctx() R10=fp0",
		"invalid mem access 'scalar'",
		"R2 invalid mem access 'scalar'",
		// Boundary / adversarial inputs.
		"",
		"'\n\t\\",
		"error: use of undeclared identifier ''",
		"error: use of undeclared identifier '''",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	catalog, err := LoadClangCatalog()
	if err != nil {
		f.Fatalf("LoadClangCatalog: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ClangCatalog.Lookup panicked on input %q: %v", input, r)
			}
		}()
		_, _, _ = catalog.Lookup(input, "")
	})
}
