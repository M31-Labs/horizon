package registry

import (
	"regexp"
	"strings"
	"testing"
)

// TestClangCatalogLoadsSeedEntries asserts the embedded catalog parses
// cleanly and exposes the v1 seed entries (CC0001–CC0006).
func TestClangCatalogLoadsSeedEntries(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	if c.Schema != ClangCatalogSchema {
		t.Fatalf("schema = %q, want %q", c.Schema, ClangCatalogSchema)
	}
	if c.Version != "1" {
		t.Fatalf("version = %q, want %q", c.Version, "1")
	}
	if len(c.Entries) < 6 {
		t.Fatalf("entries = %d, want at least 6 seed entries", len(c.Entries))
	}
	if c.Entries[0].ID != "CC0001" {
		t.Fatalf("entries[0].ID = %q, want CC0001 (document order must put bpf-specific match first)", c.Entries[0].ID)
	}
	// Spot-check the canonical 6 seed entries are all present and in order.
	wantIDs := []string{"CC0001", "CC0002", "CC0003", "CC0004", "CC0005", "CC0006"}
	for i, want := range wantIDs {
		if c.Entries[i].ID != want {
			t.Fatalf("entries[%d].ID = %q, want %q", i, c.Entries[i].ID, want)
		}
	}
}

// TestClangCatalogPatternsCompile verifies every pattern and capture
// regex in the embedded catalog parses with regexp.Compile. The loader
// already does this at parse time; this test gives the failure mode a
// named anchor that survives loader refactors.
func TestClangCatalogPatternsCompile(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	for _, e := range c.Entries {
		for _, p := range e.Match.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				t.Errorf("entry %s pattern %q: %v", e.ID, p, err)
			}
		}
		for name, frag := range e.Match.Captures {
			if _, err := regexp.Compile(frag); err != nil {
				t.Errorf("entry %s capture %q (%q): %v", e.ID, name, frag, err)
			}
		}
	}
}

// TestClangCatalogLookupMatchesExpectedEntry runs representative clang
// stderr lines through the catalog and asserts the expected (ID, HZN)
// pair fires. Table covers 4 of the 6 seed entries; the fixture corpus
// (verifier/clang_catalog_fixtures_test.go) covers all 6 end-to-end.
func TestClangCatalogLookupMatchesExpectedEntry(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	tests := []struct {
		name      string
		message   string
		wantID    string
		wantHZN   string
		wantNamed string // name of a capture key that must fire (empty = none)
		wantValue string // value of that capture (empty = unchecked)
	}{
		{
			name:      "CC0001 bpf-prefixed undeclared identifier",
			message:   "error: use of undeclared identifier 'bpf_get_current_pid_tgid'",
			wantID:    "CC0001",
			wantHZN:   "HZN3410",
			wantNamed: "identifier",
			wantValue: "bpf_get_current_pid_tgid",
		},
		{
			name:      "CC0002 generic undeclared identifier (non-bpf)",
			message:   "error: use of undeclared identifier 'helper_function'",
			wantID:    "CC0002",
			wantHZN:   "HZN3411",
			wantNamed: "identifier",
			wantValue: "helper_function",
		},
		{
			name:    "CC0004 unknown type name",
			message: "error: unknown type name 'task_struct'",
			wantID:  "CC0004",
			wantHZN: "HZN3430",
		},
		{
			name:    "CC0006 incompatible pointer types",
			message: "error: incompatible pointer types passing 'struct xdp_md *'",
			wantID:  "CC0006",
			wantHZN: "HZN3450",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entry, captures, ok := c.Lookup(tc.message, "")
			if !ok {
				t.Fatalf("Lookup(%q): no match", tc.message)
			}
			if entry.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", entry.ID, tc.wantID)
			}
			if entry.HZNCode != tc.wantHZN {
				t.Errorf("HZNCode = %q, want %q", entry.HZNCode, tc.wantHZN)
			}
			if tc.wantNamed != "" {
				got := captures[tc.wantNamed]
				if got == "" {
					t.Errorf("capture %q empty (captures = %v)", tc.wantNamed, captures)
				}
				if tc.wantValue != "" && got != tc.wantValue {
					t.Errorf("capture %q = %q, want %q", tc.wantNamed, got, tc.wantValue)
				}
			}
		})
	}
}

// TestClangCatalogLookupReturnsSentinelOnNoMatch pins the no-match
// contract: an unrelated clang-shaped message must return ok=false so
// the diagnose path can fall back to HZN3400.
func TestClangCatalogLookupReturnsSentinelOnNoMatch(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	entry, captures, ok := c.Lookup("error: something completely unrelated", "")
	if ok {
		t.Fatalf("Lookup matched on unrelated input: ID=%q", entry.ID)
	}
	if captures != nil {
		t.Fatalf("captures on no-match = %v, want nil", captures)
	}
}

// TestClangCatalogCC0001BeforeCC0002 pins the document-order invariant
// from O-8: CC0001 (bpf-prefixed) must precede CC0002 (generic) so that
// a `bpf_*` undeclared identifier gets the bpf-specific remediation
// instead of the generic "did you mean another local symbol?" path.
// Encoded as a test so reordering the JSON requires intent.
func TestClangCatalogCC0001BeforeCC0002(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	posCC0001 := -1
	posCC0002 := -1
	for i, e := range c.Entries {
		switch e.ID {
		case "CC0001":
			posCC0001 = i
		case "CC0002":
			posCC0002 = i
		}
	}
	if posCC0001 < 0 || posCC0002 < 0 {
		t.Fatalf("could not locate CC0001 (%d) and CC0002 (%d) in catalog", posCC0001, posCC0002)
	}
	if posCC0001 >= posCC0002 {
		t.Fatalf("CC0001 (index %d) must precede CC0002 (index %d): first-match-wins requires bpf-specific to win against bpf_* identifiers", posCC0001, posCC0002)
	}
	// Lookup confirmation: a bpf_-prefixed undeclared identifier must
	// match CC0001 (not CC0002).
	entry, _, ok := c.Lookup("error: use of undeclared identifier 'bpf_probe_read_user'", "")
	if !ok || entry.ID != "CC0001" {
		t.Fatalf("Lookup of bpf-prefixed identifier matched %q, want CC0001", entry.ID)
	}
}

// TestClangCatalogCC0001RemediationMentionsBothFixPaths pins O-4:
// CC0001's remediation should surface BOTH runtime/horizon_bpf.h and
// vmlinux.h regeneration as fix paths (pre-judging risks misdiagnosing
// builds that have one and need the other).
func TestClangCatalogCC0001RemediationMentionsBothFixPaths(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	var cc0001 ClangCatalogEntry
	for _, e := range c.Entries {
		if e.ID == "CC0001" {
			cc0001 = e
			break
		}
	}
	if cc0001.ID == "" {
		t.Fatalf("CC0001 not present in catalog")
	}
	for _, want := range []string{"runtime/horizon_bpf.h", "vmlinux.h"} {
		if !strings.Contains(cc0001.Remediation, want) {
			t.Errorf("CC0001 remediation missing %q (got: %q)", want, cc0001.Remediation)
		}
	}
}

// TestClangCatalogAllEntriesUseHZN34xx pins the range constraint
// encoded by the loader's validateClangEntryShape: every entry's
// hzn_code must start with HZN34. Catches accidental allocation in the
// HZN3100 (verifier) or HZN3200 (bindgen) ranges.
func TestClangCatalogAllEntriesUseHZN34xx(t *testing.T) {
	c, err := LoadClangCatalog()
	if err != nil {
		t.Fatalf("LoadClangCatalog: %v", err)
	}
	for _, e := range c.Entries {
		if !strings.HasPrefix(e.HZNCode, "HZN34") {
			t.Errorf("entry %s: hzn_code %q outside HZN34xx range", e.ID, e.HZNCode)
		}
		// HZN3400 is reserved as the no-match sentinel; classified
		// entries must use HZN3410+.
		if e.HZNCode == "HZN3400" {
			t.Errorf("entry %s: hzn_code HZN3400 is reserved as the no-match sentinel", e.ID)
		}
	}
}
