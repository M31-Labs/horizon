package verifier_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"text/template"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/verifier"
)

var updateFixtures = flag.Bool("update-fixtures", false, "regenerate testdata/verifier-fixtures expected.json baselines")

// fixtureIDPattern matches a VCxxxx directory name, allowing for an optional
// variant suffix nested directory (e.g. VC0001/variant-a). The fixture id is
// the topmost VCxxxx component on the path.
var fixtureIDPattern = regexp.MustCompile(`^VC\d{4}$`)

// TestVerifierCatalogFixtures walks the synthetic fixture corpus, enriches
// each log entry against the catalog, and snapshots the produced
// []diag.Diagnostic to <fixture>/expected.json. Pass -update-fixtures to
// rewrite the snapshots.
//
// It also enforces two invariants:
//
//  1. id-presence — every fixture's enriched diagnostics contain a note of
//     the form "verifier-catalog: <id>" for the fixture's own id, proving the
//     catalog matched (no silent fallthrough to HZN3100 no-match).
//  2. orphan-detection — every VC id in the embedded catalog has at least
//     one fixture directory.
func TestVerifierCatalogFixtures(t *testing.T) {
	root := filepath.Join("..", "testdata", "verifier-fixtures")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root missing at %s: %v", root, err)
	}

	fixtures := discoverFixtures(t, root)
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures discovered under %s — expected at least one log.txt per VC entry", root)
	}

	catalog := verifier.MustLoadCatalog()

	seenIDs := map[string]bool{}
	for _, f := range fixtures {
		f := f
		t.Run(f.testName, func(t *testing.T) {
			raw, err := os.ReadFile(f.logPath)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}
			got := enrichLog(t, catalog, string(raw))
			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatalf("marshal diagnostics: %v", err)
			}
			gotJSON = append(gotJSON, '\n')

			expectedPath := filepath.Join(f.dir, "expected.json")
			if *updateFixtures {
				if err := os.WriteFile(expectedPath, gotJSON, 0o644); err != nil {
					t.Fatalf("write expected.json: %v", err)
				}
			} else {
				want, err := os.ReadFile(expectedPath)
				if err != nil {
					t.Fatalf("read %s: %v (run `make verifier-fixtures-update`?)", expectedPath, err)
				}
				if !bytes.Equal(gotJSON, want) {
					t.Errorf("%s differs from expected.json — run `make verifier-fixtures-update` if intended\n--- got ---\n%s\n--- want ---\n%s", f.testName, string(gotJSON), string(want))
				}
			}

			// id-presence assertion: at least one diagnostic note must carry
			// the fixture's catalog id.
			wantNote := "verifier-catalog: " + f.id
			if !hasNoteContaining(got, wantNote) {
				t.Errorf("%s: no diagnostic note contains %q (got diagnostics: %s)", f.testName, wantNote, string(gotJSON))
			}
			seenIDs[f.id] = true
		})
	}

	// orphan-detection: every catalog VC id must be exercised by at least
	// one fixture directory. Skip when the user is updating fixtures, because
	// they may be mid-edit.
	if !*updateFixtures {
		var orphans []string
		for _, e := range catalog.Entries {
			if !seenIDs[e.ID] {
				orphans = append(orphans, e.ID)
			}
		}
		if len(orphans) > 0 {
			sort.Strings(orphans)
			t.Errorf("catalog entries have no fixture under %s: %s", root, strings.Join(orphans, ", "))
		}
	}
}

type fixtureCase struct {
	id       string // top-level VCxxxx id
	dir      string // absolute or relative path to fixture dir
	logPath  string
	testName string // VC0001, VC0001/variant-a, ...
}

// discoverFixtures walks root and returns one fixtureCase per directory that
// contains a log.txt. The fixture id is the topmost VCxxxx directory on the
// path (so VC0001/variant-a is owned by VC0001).
func discoverFixtures(t *testing.T, root string) []fixtureCase {
	t.Helper()
	var out []fixtureCase
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "log.txt" {
			return nil
		}
		dir := filepath.Dir(path)
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		id := parts[0]
		if !fixtureIDPattern.MatchString(id) {
			return fmt.Errorf("fixture path %s does not start with a VCxxxx dir", rel)
		}
		out = append(out, fixtureCase{
			id:       id,
			dir:      dir,
			logPath:  path,
			testName: rel,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].testName < out[j].testName })
	return out
}

// enrichLog parses the verifier log and, for each LogEntry, builds a
// diag.Diagnostic enriched against the catalog. This mirrors the enrichment
// shape Task 4 will wire into cmd/hzn/diagnose.go; the fixture test pins the
// contract independently of cmd/hzn integration so the catalog<->diagnostic
// contract is decoupled from the diagnose-path glue.
//
// Per fixture, the returned shape is the canonical-JSON []diag.Diagnostic
// snapshotted to expected.json.
func enrichLog(t *testing.T, catalog verifier.Catalog, raw string) []diag.Diagnostic {
	t.Helper()
	log := verifier.ParseLog(raw)
	out := make([]diag.Diagnostic, 0, len(log.Entries))
	for _, e := range log.Entries {
		out = append(out, enrichEntry(t, catalog, e))
	}
	return out
}

func enrichEntry(t *testing.T, catalog verifier.Catalog, e verifier.LogEntry) diag.Diagnostic {
	t.Helper()
	severity := diag.Severity(e.Severity)
	if severity == "" {
		severity = diag.SeverityError
	}
	d := diag.Diagnostic{
		Code:     "HZN3100",
		Severity: severity,
		Message:  e.Message,
	}
	entry, captures, matched := catalog.Lookup(e.Message, e.Raw)
	if matched {
		d.Code = entry.HZNCode
		d.Message = entry.Summary
		d.Suggest = renderRemediation(t, entry, captures)
		d.Notes = append(d.Notes, "verifier-catalog: "+entry.ID)
		d.Notes = append(d.Notes, "cause: "+renderTemplateString(t, "cause:"+entry.ID, entry.CommonCause, captures))
		// Only emit notes for catalog-declared capture keys; the loader
		// also populates the underlying named-subexp aliases (e.g. `reg`
		// when the catalog declares `register` over `R(?P<reg>\d+) `),
		// but those are an implementation detail and would clutter the
		// diagnostic surface.
		for _, name := range catalogCaptureKeys(entry, captures) {
			d.Notes = append(d.Notes, fmt.Sprintf("capture: %s=%s", name, captures[name]))
		}
	}
	if e.Raw != "" && e.Raw != e.Message {
		d.Notes = append(d.Notes, e.Raw)
	}
	return d
}

func renderRemediation(t *testing.T, entry verifier.CatalogEntry, captures map[string]string) string {
	return renderTemplateString(t, "remediation:"+entry.ID, entry.Remediation, captures)
}

// renderTemplateString renders a Go text/template against the captures map.
// On any parse or execute error it falls back to the original string —
// remediation copy is allowed to contain template directives but must never
// crash the test on malformed input. Catalog drift / fuzz tests catch the
// "malformed template" failure mode at load time elsewhere.
func renderTemplateString(t *testing.T, name, src string, captures map[string]string) string {
	t.Helper()
	if !strings.Contains(src, "{{") {
		return src
	}
	tpl, err := template.New(name).Parse(src)
	if err != nil {
		t.Logf("template %s parse: %v (falling back to raw string)", name, err)
		return src
	}
	var buf bytes.Buffer
	data := struct {
		Captures map[string]string
	}{Captures: captures}
	if err := tpl.Execute(&buf, data); err != nil {
		t.Logf("template %s execute: %v (falling back to raw string)", name, err)
		return src
	}
	return buf.String()
}

// catalogCaptureKeys returns the catalog-declared capture keys for an entry,
// filtered to those that actually fired (present in captures), sorted for
// determinism.
func catalogCaptureKeys(entry verifier.CatalogEntry, captures map[string]string) []string {
	if len(captures) == 0 || len(entry.Match.Captures) == 0 {
		return nil
	}
	out := make([]string, 0, len(entry.Match.Captures))
	for name := range entry.Match.Captures {
		if _, ok := captures[name]; ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func hasNoteContaining(diags []diag.Diagnostic, want string) bool {
	for _, d := range diags {
		for _, n := range d.Notes {
			if strings.Contains(n, want) {
				return true
			}
		}
	}
	return false
}
