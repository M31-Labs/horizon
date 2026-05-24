package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/emitc"
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
	if !hasNoteContaining(diagnostics[0], "generated BPF C: "+cPath+":2:5") {
		t.Fatalf("notes = %#v, want generated BPF C location", diagnostics[0].Notes)
	}
	if !hasNoteContaining(diagnostics[0], "source map: function OnExec, section tracepoint/sched/sched_process_exec, node expr") {
		t.Fatalf("notes = %#v, want source map metadata", diagnostics[0].Notes)
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
	if err := os.WriteFile(sourcePath, []byte("package probes\n\nfunc OnExec(ctx tracepoint.Exec) i32 {\n    event := ExecEvents.reserve()\n    if event == nil {\n        return 0\n    bad_access()\n}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
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
	if !strings.Contains(diagnostics[0].Suggest, "nil-check") {
		t.Fatalf("suggest = %q, want pointer safety nil-check guidance", diagnostics[0].Suggest)
	}
	if diagnostics[0].Source == nil || diagnostics[0].Source.Line != 7 || !strings.Contains(diagnostics[0].Source.Text, "bad_access") {
		t.Fatalf("source context = %#v, want authored source line", diagnostics[0].Source)
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
	if !strings.Contains(diagnostics[0].Suggest, "nil-check") {
		t.Fatalf("suggest = %q, want pointer safety nil-check guidance", diagnostics[0].Suggest)
	}
}

func TestDiagnoseMapsHelperWrapperDiagnosticToAuthoredCall(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "open.bpf.c")
	mapPath := filepath.Join(dir, "open.hznmap.json")
	logPath := filepath.Join(dir, "clang.log")

	result, err := compiler.AnalyzePath("../../examples/openwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out.SourceMap.Generated.Path = cPath
	if err := os.WriteFile(cPath, []byte(out.Code), 0o644); err != nil {
		t.Fatalf("write generated C: %v", err)
	}
	writeDiagnoseSourceMap(t, mapPath, out.SourceMap)
	line := diagnoseLineContaining(t, out.Code, "return bpf_probe_read_user_str")
	if err := os.WriteFile(logPath, []byte(fmt.Sprintf("%s:%d:12: error: use of undeclared identifier 'bpf_probe_read_user_str'\n", cPath, line)), 0o644); err != nil {
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
	if got, want := diagnostics[0].Primary.Start.Line, 24; got != want {
		t.Fatalf("primary line = %d, want %d; diagnostic = %#v", got, want, diagnostics[0])
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "bpf.probe_read_user_str") {
		t.Fatalf("source context = %#v, want authored helper call", diagnostics[0].Source)
	}
	if !hasNoteContaining(diagnostics[0], "source map: function OnOpen, section kprobe/do_sys_openat2, node helper_wrapper") {
		t.Fatalf("notes = %#v, want helper wrapper source map metadata", diagnostics[0].Notes)
	}
}

func TestDiagnoseMapsCgroupContextWrapperDiagnosticToAuthoredCall(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "connect.bpf.c")
	mapPath := filepath.Join(dir, "connect.hznmap.json")
	logPath := filepath.Join(dir, "clang.log")

	result, err := compiler.AnalyzePath("../../examples/cgroupconnect")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out.SourceMap.Generated.Path = cPath
	if err := os.WriteFile(cPath, []byte(out.Code), 0o644); err != nil {
		t.Fatalf("write generated C: %v", err)
	}
	writeDiagnoseSourceMap(t, mapPath, out.SourceMap)
	line := diagnoseLineContaining(t, out.Code, "return bpf_ntohs((__u16)ctx->user_port);")
	if err := os.WriteFile(logPath, []byte(fmt.Sprintf("%s:%d:12: error: use of undeclared identifier 'bpf_ntohs'\n", cPath, line)), 0o644); err != nil {
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
	if got, want := diagnostics[0].Primary.Start.Line, 12; got != want {
		t.Fatalf("primary line = %d, want %d; diagnostic = %#v", got, want, diagnostics[0])
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "cgroup.dst_port") {
		t.Fatalf("source context = %#v, want authored cgroup helper call", diagnostics[0].Source)
	}
	if !hasNoteContaining(diagnostics[0], "source map: function BlockSMTP, section cgroup/connect4, node cgroup_context_wrapper") {
		t.Fatalf("notes = %#v, want cgroup wrapper source map metadata", diagnostics[0].Notes)
	}
}

func TestDiagnoseFailOnErrorReturnsDiagnosticErrorAfterJSON(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "input.hzn")
	cPath := filepath.Join(dir, "input.bpf.c")
	mapPath := filepath.Join(dir, "input.hznmap.json")
	logPath := filepath.Join(dir, "verifier.log")

	sourceMap := diagnoseTestSourceMap(sourcePath, "input.bpf.c", 2)
	writeDiagnoseSourceMap(t, mapPath, sourceMap)
	if err := os.WriteFile(sourcePath, []byte("package probes\n\nfunc OnExec(ctx tracepoint.Exec) i32 {\n    event := ExecEvents.reserve()\n    if event == nil {\n        return 0\n    bad_access()\n}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(cPath, []byte("int OnExec(void *ctx) {\n    bad_access();\n}\n"), 0o644); err != nil {
		t.Fatalf("write generated C: %v", err)
	}
	if err := os.WriteFile(logPath, []byte("0: R1=ctx() R10=fp0\n; bad_access();\ninvalid mem access 'scalar'\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-map", mapPath, "-json", "-fail-on-error"})
	})
	if err == nil || err.Error() != "1 diagnostic(s)" {
		t.Fatalf("run diagnose -fail-on-error error = %v, want one diagnostic error", err)
	}

	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics after failed diagnose: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 || diagnostics[0].Severity != diag.SeverityError {
		t.Fatalf("diagnostics = %#v, want one error diagnostic", diagnostics)
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "bad_access") {
		t.Fatalf("source context = %#v, want authored source line", diagnostics[0].Source)
	}
}

func TestDiagnoseFailOnErrorIgnoresWarnings(t *testing.T) {
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
		return run([]string{"diagnose", logPath, "-map", mapPath, "-json", "-fail-on-error"})
	})
	if err != nil {
		t.Fatalf("run diagnose warning -fail-on-error: %v", err)
	}

	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 || diagnostics[0].Severity != diag.SeverityWarning {
		t.Fatalf("diagnostics = %#v, want one warning diagnostic", diagnostics)
	}
}

func TestDiagnoseAddsVerifierSpecificSuggestions(t *testing.T) {
	tests := map[string]string{
		"unreleased reference id=3 alloc_insn=8": "ringbuf reservation",
		"unbounded loop":                         "counted for loop",
		"unknown func bpf_bad#999":               "compiler-known helpers",
		"R0 !read_ok":                            "explicit i32",
		"stack depth 520":                        "BPF stack limit",
		"math between fp pointer and register":   "pointer arithmetic",
	}
	for raw, want := range tests {
		diagnostics := diagnosticsFromVerifierLog(raw, ir.SourceMap{}, nil)
		if len(diagnostics) != 1 {
			t.Fatalf("diagnostics for %q = %d, want 1", raw, len(diagnostics))
		}
		if !strings.Contains(diagnostics[0].Suggest, want) {
			t.Fatalf("suggest for %q = %q, want containing %q", raw, diagnostics[0].Suggest, want)
		}
	}
}

func diagnoseLineContaining(t *testing.T, text string, needle string) int {
	t.Helper()
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("missing %q in:\n%s", needle, text)
	return 0
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

func hasNoteContaining(diagnostic diag.Diagnostic, needle string) bool {
	for _, note := range diagnostic.Notes {
		if strings.Contains(note, needle) {
			return true
		}
	}
	return false
}
