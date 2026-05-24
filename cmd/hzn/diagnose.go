package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	diagnostics := diagnosticsFromVerifierLog(string(raw), sourceMap, generated)
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
		}
		if converted.Primary.IsZero() {
			converted.Primary = d.Generated
		}
		if !d.Generated.IsZero() {
			converted.Labels = append(converted.Labels, diag.Label{
				Span:    d.Generated,
				Message: "generated BPF C",
			})
		}
		if d.Raw != "" && d.Raw != d.Message {
			converted.Notes = append(converted.Notes, d.Raw)
		}
		out = append(out, converted)
	}
	return out
}
