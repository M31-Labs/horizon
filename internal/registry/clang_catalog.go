// ClangCatalog loader. Vendored JSON lives next to this file at
// clang-catalog-v1.json; the canonical Hyphae source is at
// ~/.hyphae/spaces/m31labs-horizon/specs/clang-catalog-v1.json.
// See spec.horizon.clang-catalog.v1.
//
// Strict sibling of verifier_catalog.go: same regex-compile-and-cache
// shape, same first-match-wins lookup, same drift / fuzz contract.
// Lives in internal/registry (alongside the verifier-message catalog)
// so the //go:embed of the JSON file is colocated with the JSON itself.
// The verifier package re-exports the public surface through
// verifier/clang_catalog.go so callers can write
// verifier.LookupClangCatalog(...).
//
// The clang catalog mirrors the verifier catalog's roles for the
// other side of the compile pipeline: clang-rooted diagnostics flow
// through the HZN34xx range (HZN3400 = no-match sentinel, HZN3410+ =
// classified entries), while verifier-rooted diagnostics flow through
// HZN31xx. The two catalogs are mutually exclusive by origin (gated
// in cmd/hzn/diagnose.go on d.Kind == "clang_diagnostic").

package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed clang-catalog-v1.json
var clangCatalogJSON []byte

// ClangCatalogSchema is the schema string the loader requires.
const ClangCatalogSchema = "m31labs.dev/horizon/clang-catalog/v1"

// ClangCatalog is the parsed clang-message catalog. Entries are
// indexed in document order; first match wins (see spec §"Match
// precedence").
type ClangCatalog struct {
	Schema  string              `json:"schema"`
	Version string              `json:"version"`
	Entries []ClangCatalogEntry `json:"entries"`

	// compiled patterns + captures, one slot per Entries index, populated
	// at load time. Kept private because callers should use Lookup.
	compiledPatterns [][]*regexp.Regexp
	compiledCaptures []map[string]*regexp.Regexp
}

// ClangCatalogEntry is one row of the catalog.
type ClangCatalogEntry struct {
	ID          string            `json:"id"`
	Summary     string            `json:"summary"`
	Match       ClangCatalogMatch `json:"match"`
	HZNCode     string            `json:"hzn_code"`
	CommonCause string            `json:"common_cause"`
	Remediation string            `json:"remediation"`
	SeeAlso     []string          `json:"see_also,omitempty"`
	Introduced  string            `json:"introduced"`
	KernelMin   string            `json:"kernel_min,omitempty"`
}

// ClangCatalogMatch declares how a clang message matches this entry.
type ClangCatalogMatch struct {
	Kind     string            `json:"kind"`
	Patterns []string          `json:"patterns"`
	Captures map[string]string `json:"captures,omitempty"`
}

// MustLoadClangCatalog parses, validates, and compiles the embedded
// catalog. Panics if anything is malformed — that would indicate a
// build-time error in the vendored file, not a runtime concern.
func MustLoadClangCatalog() ClangCatalog {
	c, err := LoadClangCatalog()
	if err != nil {
		panic(fmt.Sprintf("clang catalog: %v", err))
	}
	return c
}

// LoadClangCatalog parses the embedded catalog JSON, validates it,
// and pre-compiles every pattern and capture regex. Returns an error
// for any malformed shape — schema mismatch, missing required field,
// duplicate id, unsupported match kind, or uncompilable regex.
func LoadClangCatalog() (ClangCatalog, error) {
	return loadClangCatalogBytes(clangCatalogJSON)
}

// LoadClangCatalogBytes is exposed for fuzz testing the loader against
// externally supplied byte slices. Production callers use
// LoadClangCatalog / MustLoadClangCatalog.
func LoadClangCatalogBytes(raw []byte) (ClangCatalog, error) {
	return loadClangCatalogBytes(raw)
}

func loadClangCatalogBytes(raw []byte) (ClangCatalog, error) {
	var c ClangCatalog
	// Unknown per-entry fields are silently ignored (forward-compat:
	// older hzn binaries keep working when the vendored catalog grows
	// new fields). Schema-string validation below catches genuine
	// schema breakage.
	if err := json.Unmarshal(raw, &c); err != nil {
		return ClangCatalog{}, fmt.Errorf("parse clang catalog: %w", err)
	}
	if c.Schema != ClangCatalogSchema {
		return ClangCatalog{}, fmt.Errorf("clang catalog: unsupported schema %q (want %q)", c.Schema, ClangCatalogSchema)
	}
	if c.Version == "" {
		return ClangCatalog{}, fmt.Errorf("clang catalog: missing version")
	}
	if len(c.Entries) == 0 {
		return ClangCatalog{}, fmt.Errorf("clang catalog: no entries")
	}
	c.compiledPatterns = make([][]*regexp.Regexp, len(c.Entries))
	c.compiledCaptures = make([]map[string]*regexp.Regexp, len(c.Entries))
	seenIDs := make(map[string]bool, len(c.Entries))
	for i, e := range c.Entries {
		if err := validateClangEntryShape(e); err != nil {
			return ClangCatalog{}, fmt.Errorf("clang catalog: entry %d (%s): %w", i, e.ID, err)
		}
		if seenIDs[e.ID] {
			return ClangCatalog{}, fmt.Errorf("clang catalog: duplicate id %q", e.ID)
		}
		seenIDs[e.ID] = true
		patterns := make([]*regexp.Regexp, 0, len(e.Match.Patterns))
		for _, p := range e.Match.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return ClangCatalog{}, fmt.Errorf("clang catalog: entry %s: compile pattern %q: %w", e.ID, p, err)
			}
			patterns = append(patterns, re)
		}
		c.compiledPatterns[i] = patterns
		if len(e.Match.Captures) > 0 {
			caps := make(map[string]*regexp.Regexp, len(e.Match.Captures))
			for name, frag := range e.Match.Captures {
				re, err := regexp.Compile(frag)
				if err != nil {
					return ClangCatalog{}, fmt.Errorf("clang catalog: entry %s: compile capture %q: %w", e.ID, name, err)
				}
				caps[name] = re
			}
			c.compiledCaptures[i] = caps
		}
	}
	return c, nil
}

func validateClangEntryShape(e ClangCatalogEntry) error {
	if e.ID == "" {
		return fmt.Errorf("missing id")
	}
	if !strings.HasPrefix(e.ID, "CC") {
		return fmt.Errorf("id %q does not use CC prefix", e.ID)
	}
	if e.Summary == "" {
		return fmt.Errorf("missing summary")
	}
	if e.HZNCode == "" {
		return fmt.Errorf("missing hzn_code")
	}
	if !strings.HasPrefix(e.HZNCode, "HZN34") {
		return fmt.Errorf("hzn_code %q outside HZN34xx range", e.HZNCode)
	}
	if e.Remediation == "" {
		return fmt.Errorf("missing remediation")
	}
	if e.Introduced == "" {
		return fmt.Errorf("missing introduced")
	}
	if e.Match.Kind != "regex" {
		return fmt.Errorf("match.kind %q not supported (want \"regex\")", e.Match.Kind)
	}
	if len(e.Match.Patterns) == 0 {
		return fmt.Errorf("match.patterns is empty")
	}
	return nil
}

// Lookup returns the first catalog entry whose any pattern matches the
// joined clang text (message + "\n" + raw), along with the named
// captures extracted from the catalog's capture fragments. The third
// return reports whether any entry matched; on false, callers should
// fall back to the generic HZN3400 diagnostic.
//
// Match precedence: document order, first-match-wins. See
// spec.horizon.clang-catalog.v1 §"Match precedence".
func (c ClangCatalog) Lookup(message, raw string) (ClangCatalogEntry, map[string]string, bool) {
	text := message
	if raw != "" && raw != message {
		text = message + "\n" + raw
	}
	for i, e := range c.Entries {
		patterns := c.compiledPatterns[i]
		matched := false
		for _, re := range patterns {
			if re.MatchString(text) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		caps := captureValues(c.compiledCaptures[i], text)
		return e, caps, true
	}
	return ClangCatalogEntry{}, nil, false
}
