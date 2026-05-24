package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func TestDiagnoseJSONUsesCompilerDiagnosticShape(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "input.hzn")
	cPath := filepath.Join(dir, "input.bpf.c")
	mapPath := filepath.Join(dir, "input.hznmap.json")
	logPath := filepath.Join(dir, "clang.log")

	sourceMap := diagnoseTestSourceMap(sourcePath, cPath, 2)
	writeDiagnoseSourceMap(t, mapPath, sourceMap)
	if err := os.WriteFile(logPath, []byte(fmt.Sprintf("%s:2:5: warning: synthetic clang warning\n", cPath)), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-map", mapPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose -json: %v", err)
	}

	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Code != "HZN3100" {
		t.Fatalf("code = %q, want HZN3100", diagnostics[0].Code)
	}
	if diagnostics[0].Severity != diag.SeverityWarning {
		t.Fatalf("severity = %q, want warning", diagnostics[0].Severity)
	}
	if diagnostics[0].Primary.File != span.FileID(sourcePath) {
		t.Fatalf("primary file = %q, want %q", diagnostics[0].Primary.File, sourcePath)
	}
	if len(diagnostics[0].Labels) != 1 || diagnostics[0].Labels[0].Message != "generated BPF C" {
		t.Fatalf("labels = %#v, want generated BPF C label", diagnostics[0].Labels)
	}
}

func TestDiagnoseLoadsGeneratedSourceBesideSourceMap(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "input.hzn")
	cPath := filepath.Join(dir, "input.bpf.c")
	mapPath := filepath.Join(dir, "input.hznmap.json")
	logPath := filepath.Join(dir, "verifier.log")

	sourceMap := diagnoseTestSourceMap(sourcePath, "input.bpf.c", 2)
	writeDiagnoseSourceMap(t, mapPath, sourceMap)
	if err := os.WriteFile(cPath, []byte("int OnExec(void *ctx) {\n    bad_access();\n}\n"), 0o644); err != nil {
		t.Fatalf("write generated C: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("0: R1=ctx() R10=fp0\n; bad_access();\ninvalid mem access 'scalar'\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-map", mapPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose -json: %v", err)
	}

	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Primary.File != span.FileID(sourcePath) {
		t.Fatalf("primary file = %q, want %q", diagnostics[0].Primary.File, sourcePath)
	}
	if diagnostics[0].Primary.Start.Line != 7 {
		t.Fatalf("primary line = %d, want 7", diagnostics[0].Primary.Start.Line)
	}
}

func TestDiagnoseGeneratedFlagTakesValue(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "input.hzn")
	cPath := filepath.Join(dir, "actual.bpf.c")
	mapPath := filepath.Join(dir, "input.hznmap.json")
	logPath := filepath.Join(dir, "verifier.log")

	sourceMap := diagnoseTestSourceMap(sourcePath, "missing.bpf.c", 2)
	writeDiagnoseSourceMap(t, mapPath, sourceMap)
	if err := os.WriteFile(cPath, []byte("int OnExec(void *ctx) {\n    bad_access();\n}\n"), 0o644); err != nil {
		t.Fatalf("write generated C: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("; bad_access();\ninvalid mem access 'scalar'\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-map", mapPath, "-generated", cPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose -generated -json: %v", err)
	}

	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 || diagnostics[0].Primary.File != span.FileID(sourcePath) {
		t.Fatalf("diagnostics = %#v, want remapped authored source", diagnostics)
	}
}

func diagnoseTestSourceMap(sourcePath string, generatedPath string, generatedLine int) ir.SourceMap {
	return ir.SourceMap{
		Generated: ir.GeneratedSource{Path: generatedPath, Language: "c"},
		Mappings: []ir.SourceMapping{
			{
				Source: span.Span{
					File:  span.FileID(sourcePath),
					Start: span.Point{Line: 7, Column: 5},
					End:   span.Point{Line: 7, Column: 17},
				},
				Generated: span.Span{
					Start: span.Point{Line: generatedLine, Column: 1},
					End:   span.Point{Line: generatedLine, Column: 18},
				},
				Node:     "expr",
				Function: "OnExec",
				Section:  "tracepoint/sched/sched_process_exec",
			},
		},
	}
}

func writeDiagnoseSourceMap(t *testing.T, path string, sourceMap ir.SourceMap) {
	t.Helper()
	data, err := json.MarshalIndent(sourceMap, "", "  ")
	if err != nil {
		t.Fatalf("marshal source map: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write source map: %v", err)
	}
}
