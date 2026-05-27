package verifier

import (
	"regexp"
	"strings"
	"testing"
)

func TestCatalogLoadsSeedEntries(t *testing.T) {
	c, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if got, want := c.Schema, "m31labs.dev/horizon/verifier-catalog/v1"; got != want {
		t.Fatalf("schema = %q, want %q", got, want)
	}
	if got, want := c.Version, "1"; got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
	if len(c.Entries) < 10 {
		t.Fatalf("entries = %d, want at least 10 seed entries", len(c.Entries))
	}
	if got, want := c.Entries[0].ID, "VC0001"; got != want {
		t.Fatalf("entries[0].ID = %q, want %q", got, want)
	}
	seen := map[string]bool{}
	for _, e := range c.Entries {
		if seen[e.ID] {
			t.Fatalf("duplicate id %q", e.ID)
		}
		seen[e.ID] = true
		if !strings.HasPrefix(e.ID, "VC") {
			t.Fatalf("entry id %q missing VC prefix", e.ID)
		}
		if !strings.HasPrefix(e.HZNCode, "HZN31") {
			t.Fatalf("entry %s: hzn_code %q outside HZN31xx range", e.ID, e.HZNCode)
		}
	}
}

func TestCatalogPatternsCompile(t *testing.T) {
	c, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	for _, e := range c.Entries {
		if e.Match.Kind != "regex" {
			t.Fatalf("entry %s: match.kind = %q, want \"regex\"", e.ID, e.Match.Kind)
		}
		if len(e.Match.Patterns) == 0 {
			t.Fatalf("entry %s: no patterns", e.ID)
		}
		for _, p := range e.Match.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				t.Fatalf("entry %s: pattern %q does not compile: %v", e.ID, p, err)
			}
		}
		for name, frag := range e.Match.Captures {
			if _, err := regexp.Compile(frag); err != nil {
				t.Fatalf("entry %s: capture %s fragment %q does not compile: %v", e.ID, name, frag, err)
			}
		}
	}
}

func TestCatalogLookupMatchesExpectedEntry(t *testing.T) {
	c := MustLoadCatalog()
	tests := []struct {
		name    string
		message string
		raw     string
		wantID  string
	}{
		{
			name:    "scalar deref => VC0001",
			message: "invalid mem access 'scalar'",
			raw:     "0: R1=ctx() R10=fp0\nR2 invalid mem access 'scalar'",
			wantID:  "VC0001",
		},
		{
			name:    "inv-type deref => VC0002",
			message: "R3 invalid mem access 'inv'",
			wantID:  "VC0002",
		},
		{
			name:    "unreleased reference => VC0004",
			message: "Unreleased reference id=2",
			wantID:  "VC0004",
		},
		{
			name:    "back-edge => VC0005",
			message: "back-edge from insn 42 to 12",
			wantID:  "VC0005",
		},
		{
			name:    "BPF too large => VC0006",
			message: "BPF program is too large. Processed 1000001 insn",
			wantID:  "VC0006",
		},
		{
			name:    "unknown helper => VC0007",
			message: "unknown func bpf_probe_read_user",
			wantID:  "VC0007",
		},
		{
			name:    "R0 not set => VC0008",
			message: "R0 !read_ok",
			wantID:  "VC0008",
		},
		{
			name:    "stack too large => VC0009",
			message: "combined stack size of 3 calls is 600. Too large",
			wantID:  "VC0009",
		},
		{
			name:    "misaligned access => VC0010",
			message: "misaligned stack access",
			wantID:  "VC0010",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, _, ok := c.Lookup(tc.message, tc.raw)
			if !ok {
				t.Fatalf("Lookup(%q) returned no match", tc.message)
			}
			if entry.ID != tc.wantID {
				t.Fatalf("Lookup(%q) matched %s, want %s", tc.message, entry.ID, tc.wantID)
			}
		})
	}
}

func TestCatalogLookupReturnsSentinelOnNoMatch(t *testing.T) {
	c := MustLoadCatalog()
	entry, captures, ok := c.Lookup("completely unrelated text not in the catalog", "")
	if ok {
		t.Fatalf("Lookup matched on novel input: entry=%s", entry.ID)
	}
	if entry.ID != "" {
		t.Fatalf("no-match should return zero entry, got id=%q", entry.ID)
	}
	if captures != nil {
		t.Fatalf("no-match should return nil captures, got %v", captures)
	}
}

func TestCatalogLookupExtractsCaptures(t *testing.T) {
	c := MustLoadCatalog()
	entry, captures, ok := c.Lookup("R7 invalid mem access 'scalar'", "")
	if !ok {
		t.Fatalf("expected VC0001 match")
	}
	if entry.ID != "VC0001" {
		t.Fatalf("matched %s, want VC0001", entry.ID)
	}
	if got, want := captures["register"], "7"; got != want {
		t.Fatalf("captures[register] = %q, want %q (full captures: %v)", got, want, captures)
	}
}

func TestCatalogLookupExtractsHelperCapture(t *testing.T) {
	c := MustLoadCatalog()
	entry, captures, ok := c.Lookup("unknown func bpf_probe_read_user", "")
	if !ok {
		t.Fatalf("expected VC0007 match")
	}
	if entry.ID != "VC0007" {
		t.Fatalf("matched %s, want VC0007", entry.ID)
	}
	if got, want := captures["helper"], "probe_read_user"; got != want {
		t.Fatalf("captures[helper] = %q, want %q (full captures: %v)", got, want, captures)
	}
}
