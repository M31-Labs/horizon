// VerifierCatalog loader. Vendored JSON lives next to this file at
// verifier-catalog-v1.json; the canonical Hyphae source is at
// ~/.hyphae/spaces/m31labs-horizon/specs/verifier-catalog-v1.json.
// See spec.horizon.verifier-catalog.v1.
//
// Lives in internal/registry (alongside the capability registry) so
// the //go:embed of the JSON file is colocated with the JSON itself.
// The verifier package re-exports the public surface through
// verifier/catalog.go so callers can write verifier.LookupCatalog(...).

package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed verifier-catalog-v1.json
var verifierCatalogJSON []byte

// VerifierCatalogSchema is the schema string the loader requires.
const VerifierCatalogSchema = "m31labs.dev/horizon/verifier-catalog/v1"

// VerifierCatalog is the parsed verifier-message catalog. Entries are
// indexed in document order; first match wins (see spec §"Match
// precedence").
type VerifierCatalog struct {
	Schema  string                 `json:"schema"`
	Version string                 `json:"version"`
	Entries []VerifierCatalogEntry `json:"entries"`

	// compiled patterns + captures, one slot per Entries index, populated
	// at load time. Kept private because callers should use Lookup.
	compiledPatterns [][]*regexp.Regexp
	compiledCaptures []map[string]*regexp.Regexp
}

// VerifierCatalogEntry is one row of the catalog.
type VerifierCatalogEntry struct {
	ID          string               `json:"id"`
	Summary     string               `json:"summary"`
	Match       VerifierCatalogMatch `json:"match"`
	HZNCode     string               `json:"hzn_code"`
	CommonCause string               `json:"common_cause"`
	Remediation string               `json:"remediation"`
	SeeAlso     []string             `json:"see_also,omitempty"`
	Introduced  string               `json:"introduced"`
	KernelMin   string               `json:"kernel_min,omitempty"`
}

// VerifierCatalogMatch declares how a verifier message matches this entry.
type VerifierCatalogMatch struct {
	Kind     string            `json:"kind"`
	Patterns []string          `json:"patterns"`
	Captures map[string]string `json:"captures,omitempty"`
}

// MustLoadVerifierCatalog parses, validates, and compiles the embedded
// catalog. Panics if anything is malformed — that would indicate a
// build-time error in the vendored file, not a runtime concern.
func MustLoadVerifierCatalog() VerifierCatalog {
	c, err := LoadVerifierCatalog()
	if err != nil {
		panic(fmt.Sprintf("verifier catalog: %v", err))
	}
	return c
}

// LoadVerifierCatalog parses the embedded catalog JSON, validates it,
// and pre-compiles every pattern and capture regex. Returns an error
// for any malformed shape — schema mismatch, missing required field,
// duplicate id, unsupported match kind, or uncompilable regex.
func LoadVerifierCatalog() (VerifierCatalog, error) {
	return loadVerifierCatalogBytes(verifierCatalogJSON)
}

// LoadVerifierCatalogBytes is exposed for fuzz testing the loader
// against externally supplied byte slices. Production callers use
// LoadVerifierCatalog / MustLoadVerifierCatalog.
func LoadVerifierCatalogBytes(raw []byte) (VerifierCatalog, error) {
	return loadVerifierCatalogBytes(raw)
}

func loadVerifierCatalogBytes(raw []byte) (VerifierCatalog, error) {
	var c VerifierCatalog
	// Unknown per-entry fields are silently ignored (forward-compat:
	// older hzn binaries keep working when the vendored catalog grows
	// new fields). Schema-string validation below catches genuine
	// schema breakage.
	if err := json.Unmarshal(raw, &c); err != nil {
		return VerifierCatalog{}, fmt.Errorf("parse verifier catalog: %w", err)
	}
	if c.Schema != VerifierCatalogSchema {
		return VerifierCatalog{}, fmt.Errorf("verifier catalog: unsupported schema %q (want %q)", c.Schema, VerifierCatalogSchema)
	}
	if c.Version == "" {
		return VerifierCatalog{}, fmt.Errorf("verifier catalog: missing version")
	}
	if len(c.Entries) == 0 {
		return VerifierCatalog{}, fmt.Errorf("verifier catalog: no entries")
	}
	c.compiledPatterns = make([][]*regexp.Regexp, len(c.Entries))
	c.compiledCaptures = make([]map[string]*regexp.Regexp, len(c.Entries))
	seenIDs := make(map[string]bool, len(c.Entries))
	for i, e := range c.Entries {
		if err := validateVerifierEntryShape(e); err != nil {
			return VerifierCatalog{}, fmt.Errorf("verifier catalog: entry %d (%s): %w", i, e.ID, err)
		}
		if seenIDs[e.ID] {
			return VerifierCatalog{}, fmt.Errorf("verifier catalog: duplicate id %q", e.ID)
		}
		seenIDs[e.ID] = true
		patterns := make([]*regexp.Regexp, 0, len(e.Match.Patterns))
		for _, p := range e.Match.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return VerifierCatalog{}, fmt.Errorf("verifier catalog: entry %s: compile pattern %q: %w", e.ID, p, err)
			}
			patterns = append(patterns, re)
		}
		c.compiledPatterns[i] = patterns
		if len(e.Match.Captures) > 0 {
			caps := make(map[string]*regexp.Regexp, len(e.Match.Captures))
			for name, frag := range e.Match.Captures {
				re, err := regexp.Compile(frag)
				if err != nil {
					return VerifierCatalog{}, fmt.Errorf("verifier catalog: entry %s: compile capture %q: %w", e.ID, name, err)
				}
				caps[name] = re
			}
			c.compiledCaptures[i] = caps
		}
	}
	return c, nil
}

func validateVerifierEntryShape(e VerifierCatalogEntry) error {
	if e.ID == "" {
		return fmt.Errorf("missing id")
	}
	if !strings.HasPrefix(e.ID, "VC") {
		return fmt.Errorf("id %q does not use VC prefix", e.ID)
	}
	if e.Summary == "" {
		return fmt.Errorf("missing summary")
	}
	if e.HZNCode == "" {
		return fmt.Errorf("missing hzn_code")
	}
	if !strings.HasPrefix(e.HZNCode, "HZN31") {
		return fmt.Errorf("hzn_code %q outside HZN31xx range", e.HZNCode)
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
// joined verifier text (message + "\n" + raw), along with the named
// captures extracted from the catalog's capture fragments. The third
// return reports whether any entry matched; on false, callers should
// fall back to the generic HZN3100 diagnostic.
//
// Match precedence: document order, first-match-wins. See
// spec.horizon.verifier-catalog.v1 §"Match precedence".
func (c VerifierCatalog) Lookup(message, raw string) (VerifierCatalogEntry, map[string]string, bool) {
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
	return VerifierCatalogEntry{}, nil, false
}

// captureValues runs each capture regex against the text and returns
// the first named submatch per capture. Nil if there are no captures
// or no captures fired.
func captureValues(captures map[string]*regexp.Regexp, text string) map[string]string {
	if len(captures) == 0 {
		return nil
	}
	out := map[string]string{}
	for name, re := range captures {
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		names := re.SubexpNames()
		for i, sub := range names {
			if sub == "" {
				continue
			}
			if i < len(m) && m[i] != "" {
				out[sub] = m[i]
			}
		}
		// Fallback: if the regex has no named subexp but produced a
		// match group, use the first group as the value under the
		// capture key. This keeps captures useful for fragments like
		// "bpf_(\\w+)" without forcing every catalog author to name
		// every group.
		if _, named := out[name]; !named && len(m) > 1 && m[1] != "" {
			out[name] = m[1]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
