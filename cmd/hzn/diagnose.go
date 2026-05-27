package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/verifier"
)

// verifierCatalog is the parsed verifier-message catalog used to enrich
// diagnostics produced from verifier logs. Loaded once at package init via
// the //go:embed-backed registry loader; a panic here means the vendored
// JSON or the loader is broken at build time.
var verifierCatalog = verifier.MustLoadCatalog()

// catalogTemplateCache holds parsed text/templates for remediation and
// common-cause strings, keyed by "<entry-id>:<field>". text/template parses
// are not cheap relative to per-diagnostic emission, and the catalog is
// effectively immutable for the process lifetime, so caching is a clear win.
var (
	catalogTemplateCache sync.Map // map[string]*template.Template
)

func runDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	mapPath := fs.String("map", "", "source map path")
	generatedPath := fs.String("generated", "", "generated BPF C path")
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
	failOnError := fs.Bool("fail-on-error", false, "return a non-zero diagnostic error when remapped diagnostics contain errors")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("diagnose requires a clang or verifier log path, or - for stdin")
	}
	raw, err := readDiagnoseLog(fs.Arg(0))
	if err != nil {
		return err
	}
	var sourceMap ir.SourceMap
	if *mapPath != "" {
		data, err := os.ReadFile(*mapPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &sourceMap); err != nil {
			return err
		}
	}
	generated, err := readDiagnoseGenerated(*generatedPath, *mapPath, sourceMap)
	if err != nil {
		return err
	}
	diagnostics := diagnosticsWithPrimarySourceContext(diagnosticsFromVerifierLog(string(raw), sourceMap, generated))
	if *jsonOut {
		data, err := json.MarshalIndent(diagnostics, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		return diagnoseExitError(diagnostics, *failOnError)
	}
	for _, d := range diagnostics {
		fmt.Println(d.Format())
		for _, label := range d.Labels {
			if label.Message == "generated BPF C" && !label.Span.IsZero() {
				fmt.Printf("  generated: %s:%d:%d\n", label.Span.File, label.Span.Start.Line, label.Span.Start.Column)
				if label.Source != nil && label.Source.Text != "" {
					fmt.Printf("  %4d | %s\n", label.Source.Line, label.Source.Text)
					if label.Source.Marker != "" {
						fmt.Printf("       | %s\n", label.Source.Marker)
					}
				}
			}
		}
	}
	return diagnoseExitError(diagnostics, *failOnError)
}

func diagnoseExitError(diagnostics []diag.Diagnostic, failOnError bool) error {
	if !failOnError || !diag.HasErrors(diagnostics) {
		return nil
	}
	return errDiagnostics(errorDiagnosticCount(diagnostics))
}

func errorDiagnosticCount(diagnostics []diag.Diagnostic) int {
	count := 0
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "" || diagnostic.Severity == diag.SeverityError {
			count++
		}
	}
	return count
}

func readDiagnoseLog(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func readDiagnoseGenerated(explicitPath string, mapPath string, sourceMap ir.SourceMap) ([]byte, error) {
	if explicitPath != "" {
		return os.ReadFile(explicitPath)
	}
	if sourceMap.Generated.Path == "" {
		return nil, nil
	}
	for _, path := range generatedCandidates(sourceMap.Generated.Path, mapPath) {
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
	}
	return nil, nil
}

func generatedCandidates(generatedPath string, mapPath string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		out = append(out, path)
	}
	add(generatedPath)
	if mapPath != "" && !filepath.IsAbs(generatedPath) {
		mapDir := filepath.Dir(mapPath)
		add(filepath.Join(mapDir, generatedPath))
		add(filepath.Join(mapDir, filepath.Base(generatedPath)))
	}
	return out
}

func diagnosticsFromVerifierLog(raw string, sourceMap ir.SourceMap, generated []byte) []diag.Diagnostic {
	remapped := verifier.RemapWithGenerated(verifier.ParseLog(raw), sourceMap, generated)
	if len(remapped) == 0 && raw == "" {
		return []diag.Diagnostic{}
	}
	if len(remapped) == 0 {
		remapped = []verifier.Diagnostic{{Message: raw, Severity: "error", Raw: raw}}
	}
	return diagnosticsFromVerifier(remapped, generated)
}

func diagnosticsFromVerifier(remapped []verifier.Diagnostic, generated []byte) []diag.Diagnostic {
	out := make([]diag.Diagnostic, 0, len(remapped))
	for _, d := range remapped {
		severity := diag.Severity(d.Severity)
		if severity == "" || severity == "fatal error" {
			severity = diag.SeverityError
		}
		converted := diag.Diagnostic{
			Code:     "HZN3100",
			Severity: severity,
			Message:  d.Message,
			Primary:  d.Span,
		}
		// Origin gate (plan Task 5.4): the verifier-message catalog is
		// content-indexed, so a clang error whose text happens to contain
		// a verifier idiom (e.g., "invalid mem access 'scalar'") would
		// otherwise leak verifier remediation into a clang-rooted
		// diagnostic. Clang and verifier are different vocabularies; the
		// catalog targets the verifier vocabulary only. Synthetic fallback
		// diagnostics (Kind == "") fall through to the catalog: those
		// originate from raw verifier-log stdin without recognisable
		// per-line structure, and treating them as verifier-by-default
		// preserves the pre-gate match behaviour for those callers.
		var (
			entry    verifier.CatalogEntry
			captures map[string]string
			matched  bool
		)
		if d.Kind != "clang_diagnostic" {
			entry, captures, matched = verifierCatalog.Lookup(d.Message, d.Raw)
		}
		if matched {
			converted.Code = entry.HZNCode
			converted.Suggest = renderCatalogTemplate(entry.ID, "remediation", entry.Remediation, captures)
			converted.Notes = append(converted.Notes, "verifier-catalog: "+entry.ID)
			if entry.CommonCause != "" {
				converted.Notes = append(converted.Notes, "cause: "+renderCatalogTemplate(entry.ID, "cause", entry.CommonCause, captures))
			}
			for _, name := range catalogCaptureKeys(entry, captures) {
				converted.Notes = append(converted.Notes, fmt.Sprintf("capture: %s=%s", name, captures[name]))
			}
		} else {
			converted.Suggest = ""
		}
		if converted.Primary.IsZero() {
			converted.Primary = d.Generated
		}
		if !d.Generated.IsZero() {
			label := diag.Label{
				Span:    d.Generated,
				Message: "generated BPF C",
			}
			if source, ok := diag.SourceContext(d.Generated, generated); ok {
				label.Source = source
			}
			converted.Labels = append(converted.Labels, label)
			converted.Notes = append(converted.Notes, fmt.Sprintf("generated BPF C: %s:%d:%d", d.Generated.File, d.Generated.Start.Line, d.Generated.Start.Column))
		}
		if d.Function != "" || d.Section != "" || d.Node != "" {
			converted.Notes = append(converted.Notes, sourceMapNote(d))
		}
		if d.Mapping == "nearest" {
			converted.Notes = append(converted.Notes, "location was mapped to the nearest preceding Horizon source span")
		}
		if d.Raw != "" && d.Raw != d.Message {
			converted.Notes = append(converted.Notes, d.Raw)
		}
		out = append(out, converted)
	}
	return out
}

// renderCatalogTemplate parses and renders a catalog template string against
// the captures map. Parses are cached per (entry-id, field) so repeated
// diagnostics for the same entry skip the parse cost. On any parse or
// execute error, the raw source string is returned unchanged — remediation
// copy must never crash diagnostics on malformed templates; the catalog
// drift / fuzz harness covers the malformed-template failure mode at load
// time.
func renderCatalogTemplate(entryID, field, src string, captures map[string]string) string {
	if !strings.Contains(src, "{{") {
		return src
	}
	key := entryID + ":" + field
	var tpl *template.Template
	if cached, ok := catalogTemplateCache.Load(key); ok {
		tpl = cached.(*template.Template)
	} else {
		parsed, err := template.New(key).Parse(src)
		if err != nil {
			return src
		}
		catalogTemplateCache.Store(key, parsed)
		tpl = parsed
	}
	var buf bytes.Buffer
	data := struct {
		Captures map[string]string
	}{Captures: captures}
	if err := tpl.Execute(&buf, data); err != nil {
		return src
	}
	return buf.String()
}

// catalogCaptureKeys returns the catalog-declared capture keys for an
// entry, filtered to those that actually fired (present in captures), in
// sorted order for deterministic note emission.
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

func sourceMapNote(d verifier.Diagnostic) string {
	var parts []string
	if d.Function != "" {
		parts = append(parts, "function "+d.Function)
	}
	if d.Section != "" {
		parts = append(parts, "section "+d.Section)
	}
	if d.Node != "" {
		parts = append(parts, "node "+d.Node)
	}
	return "source map: " + strings.Join(parts, ", ")
}
