package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/verifier"
)

func runDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	mapPath := fs.String("map", "", "source map path")
	generatedPath := fs.String("generated", "", "generated BPF C path")
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
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
		_, err = os.Stdout.Write(data)
		return err
	}
	for _, d := range diagnostics {
		fmt.Println(d.Format())
		for _, label := range d.Labels {
			if label.Message == "generated BPF C" && !label.Span.IsZero() {
				fmt.Printf("  generated: %s:%d:%d\n", label.Span.File, label.Span.Start.Line, label.Span.Start.Column)
			}
		}
	}
	return nil
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
	return diagnosticsFromVerifier(remapped)
}

func diagnosticsFromVerifier(remapped []verifier.Diagnostic) []diag.Diagnostic {
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
			Suggest:  verifierSuggestion(d),
		}
		if converted.Primary.IsZero() {
			converted.Primary = d.Generated
		}
		if !d.Generated.IsZero() {
			converted.Labels = append(converted.Labels, diag.Label{
				Span:    d.Generated,
				Message: "generated BPF C",
			})
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

func verifierSuggestion(d verifier.Diagnostic) string {
	text := strings.ToLower(d.Message + "\n" + d.Raw)
	switch {
	case strings.Contains(text, "invalid mem access") || strings.Contains(text, "cannot access"):
		return "prove pointer safety in .hzn before dereference: nil-check map lookup, ringbuf reserve, or packet helper results and keep using the checked local"
	case strings.Contains(text, "unreleased reference"):
		return "submit or discard every ringbuf reservation on all return paths"
	case strings.Contains(text, "unbounded"):
		return "use a counted for loop with a literal or integer const upper bound"
	case strings.Contains(text, "unknown func"):
		return "use only Horizon compiler-known helpers for this program kind, or add a typed helper wrapper before calling it"
	case strings.Contains(text, "r0 !read_ok"):
		return "return an explicit i32 action or value on every control-flow path"
	case strings.Contains(text, "stack depth"):
		return "move large local records into maps or ringbuf reservations to stay within the BPF stack limit"
	case strings.Contains(text, "out of bounds"):
		return "use Horizon packet helpers and nil checks so bounds are proven before reading packet data"
	case strings.Contains(text, "permission denied"):
		return "check the attach type, helper availability, and capability manifest kernel requirements for this program"
	case strings.Contains(text, "math between"):
		return "avoid raw pointer arithmetic in .hzn; use compiler-known packet and map helpers that carry verifier-safe bounds"
	default:
		return ""
	}
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
