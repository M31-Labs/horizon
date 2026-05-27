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

// updateClangFixtures regenerates the testdata/clang-fixtures expected.json
// baselines. Mirrors -update-fixtures from catalog_fixtures_test.go; the
// flag name is namespaced (-update-clang-fixtures) so the two corpora can
// be refreshed independently.
var updateClangFixtures = flag.Bool("update-clang-fixtures", false, "regenerate testdata/clang-fixtures expected.json baselines")

// clangFixtureIDPattern matches a CCxxxx directory name, allowing for an
// optional variant suffix nested directory (e.g. CC0001/variant-a). The
// fixture id is the topmost CCxxxx component on the path.
var clangFixtureIDPattern = regexp.MustCompile(`^CC\d{4}$`)

// TestClangCatalogFixtures walks the synthetic clang fixture corpus,
// enriches each clang_diagnostic log entry against the catalog, and
// snapshots the produced []diag.Diagnostic to <fixture>/expected.json.
// Pass -update-clang-fixtures to rewrite the snapshots.
//
// Strict sibling of TestVerifierCatalogFixtures. Enforces the same two
// invariants:
//
//  1. id-presence — every fixture's enriched diagnostics contain a note of
//     the form "clang-catalog: <id>" for the fixture's own id, proving the
//     catalog matched (no silent fallthrough to HZN3400 no-match).
//  2. orphan-detection — every CC id in the embedded catalog has at least
//     one fixture directory.
func TestClangCatalogFixtures(t *testing.T) {
	root := filepath.Join("..", "testdata", "clang-fixtures")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root missing at %s: %v", root, err)
	}

	fixtures := discoverClangFixtures(t, root)
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures discovered under %s — expected at least one log.txt per CC entry", root)
	}

	catalog := verifier.MustLoadClangCatalog()

	seenIDs := map[string]bool{}
	for _, f := range fixtures {
		f := f
		t.Run(f.testName, func(t *testing.T) {
			raw, err := os.ReadFile(f.logPath)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}
			got := enrichClangLog(t, catalog, string(raw))
			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatalf("marshal diagnostics: %v", err)
			}
			gotJSON = append(gotJSON, '\n')

			expectedPath := filepath.Join(f.dir, "expected.json")
			if *updateClangFixtures {
				if err := os.WriteFile(expectedPath, gotJSON, 0o644); err != nil {
					t.Fatalf("write expected.json: %v", err)
				}
			} else {
				want, err := os.ReadFile(expectedPath)
				if err != nil {
					t.Fatalf("read %s: %v (run `make clang-fixtures-update`?)", expectedPath, err)
				}
				if !bytes.Equal(gotJSON, want) {
					t.Errorf("%s differs from expected.json — run `make clang-fixtures-update` if intended\n--- got ---\n%s\n--- want ---\n%s", f.testName, string(gotJSON), string(want))
				}
			}

			// id-presence assertion: at least one diagnostic note must carry
			// the fixture's catalog id.
			wantNote := "clang-catalog: " + f.id
			if !hasClangNoteContaining(got, wantNote) {
				t.Errorf("%s: no diagnostic note contains %q (got diagnostics: %s)", f.testName, wantNote, string(gotJSON))
			}
			seenIDs[f.id] = true
		})
	}

	// orphan-detection: every catalog CC id must be exercised by at least
	// one fixture directory. Skip when the user is updating fixtures, because
	// they may be mid-edit.
	if !*updateClangFixtures {
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

type clangFixtureCase struct {
	id       string // top-level CCxxxx id
	dir      string // absolute or relative path to fixture dir
	logPath  string
	testName string // CC0001, CC0001/variant-a, ...
}

// discoverClangFixtures walks root and returns one clangFixtureCase per
// directory that contains a log.txt. The fixture id is the topmost
// CCxxxx directory on the path (so CC0001/variant-a is owned by CC0001).
func discoverClangFixtures(t *testing.T, root string) []clangFixtureCase {
	t.Helper()
	var out []clangFixtureCase
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
		if !clangFixtureIDPattern.MatchString(id) {
			return fmt.Errorf("fixture path %s does not start with a CCxxxx dir", rel)
		}
		out = append(out, clangFixtureCase{
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

// enrichClangLog parses the clang log and, for each clang_diagnostic
// LogEntry, builds a diag.Diagnostic enriched against the clang catalog.
// Mirrors the enrichment shape wired into cmd/hzn/diagnose.go (Step 7.6);
// the fixture test pins the contract independently of cmd/hzn integration
// so the catalog<->diagnostic contract is decoupled from the diagnose-path
// glue.
//
// Per fixture, the returned shape is the canonical-JSON []diag.Diagnostic
// snapshotted to expected.json.
//
// Note: only clang_diagnostic entries (Kind == "clang_diagnostic") are
// enriched. Verifier-shaped lines in the same log would be skipped at the
// gate — but the fixture corpus only contains clang stderr, so every
// recognised entry is a clang one.
func enrichClangLog(t *testing.T, catalog verifier.ClangCatalog, raw string) []diag.Diagnostic {
	t.Helper()
	log := verifier.ParseLog(raw)
	out := make([]diag.Diagnostic, 0, len(log.Entries))
	for _, e := range log.Entries {
		if e.Kind != "clang_diagnostic" {
			continue
		}
		out = append(out, enrichClangEntry(t, catalog, e))
	}
	return out
}

func enrichClangEntry(t *testing.T, catalog verifier.ClangCatalog, e verifier.LogEntry) diag.Diagnostic {
	t.Helper()
	severity := diag.Severity(e.Severity)
	if severity == "" {
		severity = diag.SeverityError
	}
	d := diag.Diagnostic{
		Code:     "HZN3400",
		Severity: severity,
		Message:  e.Message,
	}
	entry, captures, matched := catalog.Lookup(e.Message, e.Raw)
	if matched {
		d.Code = entry.HZNCode
		d.Message = entry.Summary
		d.Suggest = renderClangRemediation(t, entry, captures)
		d.Notes = append(d.Notes, "clang-catalog: "+entry.ID)
		d.Notes = append(d.Notes, "cause: "+renderClangTemplateString(t, "cause:"+entry.ID, entry.CommonCause, captures))
		// Only emit notes for catalog-declared capture keys.
		for _, name := range clangCatalogCaptureKeys(entry, captures) {
			d.Notes = append(d.Notes, fmt.Sprintf("capture: %s=%s", name, captures[name]))
		}
	}
	if e.Raw != "" && e.Raw != e.Message {
		d.Notes = append(d.Notes, e.Raw)
	}
	return d
}

func renderClangRemediation(t *testing.T, entry verifier.ClangCatalogEntry, captures map[string]string) string {
	return renderClangTemplateString(t, "remediation:"+entry.ID, entry.Remediation, captures)
}

// renderClangTemplateString renders a Go text/template against the captures
// map. On any parse or execute error it falls back to the original string —
// remediation copy is allowed to contain template directives but must never
// crash the test on malformed input. Catalog drift / fuzz tests catch the
// "malformed template" failure mode at load time elsewhere.
func renderClangTemplateString(t *testing.T, name, src string, captures map[string]string) string {
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

// clangCatalogCaptureKeys returns the catalog-declared capture keys for a
// clang entry, filtered to those that actually fired, sorted for
// determinism. Test-local helper; the production path in cmd/hzn has its
// own copy keyed against the same shape.
func clangCatalogCaptureKeys(entry verifier.ClangCatalogEntry, captures map[string]string) []string {
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

func hasClangNoteContaining(diags []diag.Diagnostic, want string) bool {
	for _, d := range diags {
		for _, n := range d.Notes {
			if strings.Contains(n, want) {
				return true
			}
		}
	}
	return false
}
