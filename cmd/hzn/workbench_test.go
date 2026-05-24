package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func TestWorkbenchWritesAuthoringArtifactsWithoutObject(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "golden", "exec", "input.hzn")
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

func TestWorkbenchWritesDiagnosticReportForInvalidInput(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "invalid", "packet_unproven_read.hzn")
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

func hasDiagnosticCode(diags []diag.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
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
