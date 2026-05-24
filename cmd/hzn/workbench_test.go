package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func TestWorkbenchWritesAuthoringArtifactsWithoutObject(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "golden", "exec", "input.hzn")
	if err := os.WriteFile(filepath.Join(outDir, "input.bpf.o"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale object: %v", err)
	}
	if err := run([]string{"workbench", input, "-o", outDir}); err != nil {
		t.Fatalf("run workbench: %v", err)
	}

	for _, name := range []string{
		"input.bpf.c",
		"input.hznmap.json",
		"input.bindings.go",
		"input.cap.json",
		"input.diagnostics.json",
		"input.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "input.bpf.o")); !os.IsNotExist(err) {
		t.Fatalf("object artifact should not exist without -compile: %v", err)
	}

	var report workbenchReport
	data, err := os.ReadFile(filepath.Join(outDir, "input.report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Status != "generated" {
		t.Fatalf("status = %q, want generated", report.Status)
	}
	if report.Compile {
		t.Fatal("compile = true, want false")
	}
	if report.Paths.Object != "" {
		t.Fatalf("object path = %q, want empty without -compile", report.Paths.Object)
	}
	if report.DiagnosticCount != 0 {
		t.Fatalf("diagnostic count = %d, want 0", report.DiagnosticCount)
	}
	if len(report.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", report.Diagnostics)
	}
	if len(report.Artifacts) != 6 {
		t.Fatalf("artifacts = %d, want 6", len(report.Artifacts))
	}

	var diagnostics []struct {
		Code string `json:"code"`
	}
	data, err = os.ReadFile(filepath.Join(outDir, "input.diagnostics.json"))
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics artifact = %#v, want empty", diagnostics)
	}
}

func TestWorkbenchJSONOutput(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "golden", "exec", "input.hzn")
	stdout, err := captureStdout(t, func() error {
		return run([]string{"workbench", input, "-o", outDir, "-json"})
	})
	if err != nil {
		t.Fatalf("run workbench -json: %v", err)
	}

	var report workbenchReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal stdout report: %v\n%s", err, stdout)
	}
	if report.Schema != "m31labs.dev/horizon/report/v0" {
		t.Fatalf("schema = %q, want report schema", report.Schema)
	}
	if report.Status != "generated" {
		t.Fatalf("status = %q, want generated", report.Status)
	}
	if report.DiagnosticCount != 0 {
		t.Fatalf("diagnostic count = %d, want 0", report.DiagnosticCount)
	}
	if len(report.Artifacts) != 6 {
		t.Fatalf("artifacts = %d, want 6", len(report.Artifacts))
	}
}

func TestWorkbenchJSONOutputForInvalidInput(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "invalid", "packet_unproven_read.hzn")
	stdout, err := captureStdout(t, func() error {
		return run([]string{"workbench", input, "-o", outDir, "-json"})
	})
	if err == nil {
		t.Fatal("run workbench -json succeeded, want diagnostics error")
	}

	var report workbenchReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal stdout report: %v\n%s", err, stdout)
	}
	if report.Status != "diagnostic_error" {
		t.Fatalf("status = %q, want diagnostic_error", report.Status)
	}
	if report.DiagnosticCount == 0 {
		t.Fatal("diagnostic count = 0, want at least one")
	}
	if !hasDiagnosticCode(report.Diagnostics, "HZN2600") {
		t.Fatalf("report diagnostics = %#v, want HZN2600", report.Diagnostics)
	}
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(report.Artifacts))
	}
}

func TestWorkbenchGeneratesTypedMapBindingsForExecCount(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "examples", "execcount")
	if err := run([]string{"workbench", input, "-o", outDir}); err != nil {
		t.Fatalf("run workbench: %v", err)
	}
	bindings, err := os.ReadFile(filepath.Join(outDir, "count.bindings.go"))
	if err != nil {
		t.Fatalf("read bindings: %v", err)
	}
	for _, want := range []string{
		"type Count struct",
		"func (o *Objects) LookupExecCounts(key uint32) (Count, bool, error)",
		"func (o *Objects) UpdateExecCounts(key uint32, value Count) error",
		"func (o *Objects) ForEachExecCounts(handle func(key uint32, value Count) error) error",
		"func (o *Objects) DeleteExecCounts(key uint32) error",
	} {
		if !strings.Contains(string(bindings), want) {
			t.Fatalf("bindings missing %q:\n%s", want, bindings)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(outDir, "count.cap.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	for _, want := range []string{
		`"name": "ExecCounts"`,
		`"key": "u32"`,
		`"value": "Count"`,
		`"name": "Count"`,
		`"name": "seen"`,
		`"type": "u64"`,
	} {
		if !strings.Contains(string(manifest), want) {
			t.Fatalf("manifest missing %q:\n%s", want, manifest)
		}
	}
}

func TestWorkbenchWritesDiagnosticReportForInvalidInput(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "invalid", "packet_unproven_read.hzn")
	if err := os.WriteFile(filepath.Join(outDir, "packet_unproven_read.bpf.o"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale object: %v", err)
	}
	if err := run([]string{"workbench", input, "-o", outDir}); err == nil {
		t.Fatal("run workbench succeeded, want diagnostics error")
	}

	for _, name := range []string{
		"packet_unproven_read.diagnostics.json",
		"packet_unproven_read.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing diagnostic artifact %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"packet_unproven_read.bpf.c",
		"packet_unproven_read.hznmap.json",
		"packet_unproven_read.bindings.go",
		"packet_unproven_read.cap.json",
		"packet_unproven_read.bpf.o",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); !os.IsNotExist(err) {
			t.Fatalf("generated artifact %s should not exist for invalid input: %v", name, err)
		}
	}

	var report workbenchReport
	data, err := os.ReadFile(filepath.Join(outDir, "packet_unproven_read.report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Status != "diagnostic_error" {
		t.Fatalf("status = %q, want diagnostic_error", report.Status)
	}
	if report.DiagnosticCount == 0 {
		t.Fatal("diagnostic count = 0, want at least one")
	}
	if !hasDiagnosticCode(report.Diagnostics, "HZN2600") {
		t.Fatalf("report diagnostics = %#v, want HZN2600", report.Diagnostics)
	}
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(report.Artifacts))
	}

	data, err = os.ReadFile(filepath.Join(outDir, "packet_unproven_read.diagnostics.json"))
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var diagnostics []struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v", err)
	}
	if !hasDiagnosticCodeLite(diagnostics, "HZN2600") {
		t.Fatalf("diagnostics artifact = %#v, want HZN2600", diagnostics)
	}
}

func TestWorkbenchReportsClangDiagnostics(t *testing.T) {
	outDir := t.TempDir()
	fakeBin := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "golden", "exec", "input.hzn")
	cPath := filepath.Join(outDir, "input.bpf.c")
	if err := os.WriteFile(filepath.Join(outDir, "input.bpf.o"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale object: %v", err)
	}
	fakeClang := filepath.Join(fakeBin, "clang")
	output := cPath + ":57:5: error: synthetic clang failure"
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q >&2\nexit 1\n", output)
	if err := os.WriteFile(fakeClang, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake clang: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := run([]string{"workbench", input, "-o", outDir, "-compile"}); err == nil {
		t.Fatal("run workbench -compile succeeded, want clang error")
	}
	if _, err := os.Stat(filepath.Join(outDir, "input.bpf.o")); !os.IsNotExist(err) {
		t.Fatalf("object artifact should not exist on clang failure: %v", err)
	}

	var report workbenchReport
	data, err := os.ReadFile(filepath.Join(outDir, "input.report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Status != "clang_error" {
		t.Fatalf("status = %q, want clang_error", report.Status)
	}
	if report.Clang == "" {
		t.Fatal("clang output is empty")
	}
	if report.DiagnosticCount == 0 || !hasDiagnosticCode(report.Diagnostics, "HZN3100") {
		t.Fatalf("diagnostics = %#v, want HZN3100", report.Diagnostics)
	}
	if report.Diagnostics[0].Primary.File != "../../testdata/golden/exec/input.hzn" {
		t.Fatalf("primary file = %q, want authored input", report.Diagnostics[0].Primary.File)
	}
	if artifactsContain(report.Artifacts, filepath.Join(outDir, "input.bpf.o")) {
		t.Fatalf("artifacts include missing object: %#v", report.Artifacts)
	}

	data, err = os.ReadFile(filepath.Join(outDir, "input.diagnostics.json"))
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v", err)
	}
	if !hasDiagnosticCode(diagnostics, "HZN3100") {
		t.Fatalf("diagnostics artifact = %#v, want HZN3100", diagnostics)
	}
}

func hasDiagnosticCode(diags []diag.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

func artifactsContain(artifacts []string, path string) bool {
	for _, artifact := range artifacts {
		if artifact == path {
			return true
		}
	}
	return false
}

func hasDiagnosticCodeLite(diags []struct {
	Code string `json:"code"`
}, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	closeErr := w.Close()
	os.Stdout = old
	data, readErr := io.ReadAll(r)
	if err := r.Close(); readErr == nil {
		readErr = err
	}
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	if runErr == nil {
		runErr = closeErr
	}
	return string(data), runErr
}
