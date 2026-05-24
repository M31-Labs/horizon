package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
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
	assertReportProvenance(t, report)
	if report.Compile {
		t.Fatal("compile = true, want false")
	}
	if report.Paths.Object != "" {
		t.Fatalf("object path = %q, want empty without -compile", report.Paths.Object)
	}
	assertSourceDetail(t, report, input)
	if report.DiagnosticCount != 0 {
		t.Fatalf("diagnostic count = %d, want 0", report.DiagnosticCount)
	}
	if len(report.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", report.Diagnostics)
	}
	if len(report.Artifacts) != 6 {
		t.Fatalf("artifacts = %d, want 6", len(report.Artifacts))
	}
	for _, kind := range []string{"bpf_c", "source_map", "bindings", "capabilities", "diagnostics"} {
		assertArtifactDetail(t, report, kind)
	}
	if _, ok := artifactDetailByKind(report.ArtifactDetails, "bpf_object"); ok {
		t.Fatalf("artifact details include object without -compile: %#v", report.ArtifactDetails)
	}
	if _, ok := artifactDetailByKind(report.ArtifactDetails, "report"); ok {
		t.Fatalf("artifact details should not include self-referential report: %#v", report.ArtifactDetails)
	}
	assertRemovedStaleArtifacts(t, report, []string{filepath.Join(outDir, "input.bpf.o")})

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
	assertReportProvenance(t, report)
	if report.DiagnosticCount != 0 {
		t.Fatalf("diagnostic count = %d, want 0", report.DiagnosticCount)
	}
	assertSourceDetail(t, report, input)
	if len(report.Artifacts) != 6 {
		t.Fatalf("artifacts = %d, want 6", len(report.Artifacts))
	}
	assertArtifactDetail(t, report, "bpf_c")
	assertArtifactDetail(t, report, "diagnostics")
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
	assertReportProvenance(t, report)
	if report.DiagnosticCount == 0 {
		t.Fatal("diagnostic count = 0, want at least one")
	}
	if !hasDiagnosticCode(report.Diagnostics, "HZN2600") {
		t.Fatalf("report diagnostics = %#v, want HZN2600", report.Diagnostics)
	}
	assertSourceDetail(t, report, input)
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(report.Artifacts))
	}
	assertArtifactDetail(t, report, "diagnostics")
	if len(report.ArtifactDetails) != 1 {
		t.Fatalf("artifact details = %#v, want diagnostics only", report.ArtifactDetails)
	}
}

func TestWorkbenchWritesDiagnosticReportForSyntaxError(t *testing.T) {
	outDir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "syntax_error.hzn")
	if err := os.WriteFile(sourcePath, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if {
        return 0
    }
}
`), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	stale := writeStaleArtifacts(t, artifactPathsFor(outDir, "syntax_error").allArtifacts()...)
	stdout, err := captureStdout(t, func() error {
		return run([]string{"workbench", sourcePath, "-o", outDir, "-json"})
	})
	if err == nil {
		t.Fatal("run workbench -json succeeded, want syntax diagnostic error")
	}

	var report workbenchReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal stdout report: %v\n%s", err, stdout)
	}
	if report.Status != "diagnostic_error" {
		t.Fatalf("status = %q, want diagnostic_error", report.Status)
	}
	assertReportProvenance(t, report)
	assertRemovedStaleArtifacts(t, report, stale)
	if report.DiagnosticCount != 1 || !hasDiagnosticCode(report.Diagnostics, "HZN0100") {
		t.Fatalf("diagnostics = %#v, want one HZN0100", report.Diagnostics)
	}
	if report.Diagnostics[0].Primary.File != "syntax_error.hzn" && string(report.Diagnostics[0].Primary.File) != sourcePath {
		t.Fatalf("primary file = %q, want source path", report.Diagnostics[0].Primary.File)
	}
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want diagnostics and report only", len(report.Artifacts))
	}
	assertArtifactDetail(t, report, "diagnostics")
	for _, name := range []string{
		"syntax_error.bpf.c",
		"syntax_error.hznmap.json",
		"syntax_error.bindings.go",
		"syntax_error.cap.json",
		"syntax_error.bpf.o",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); !os.IsNotExist(err) {
			t.Fatalf("generated artifact %s should not exist for syntax error: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "syntax_error.diagnostics.json"))
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v", err)
	}
	if !hasDiagnosticCode(diagnostics, "HZN0100") {
		t.Fatalf("diagnostics artifact = %#v, want HZN0100", diagnostics)
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
	stale := writeStaleArtifacts(t, artifactPathsFor(outDir, "packet_unproven_read").allArtifacts()...)
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
	assertReportProvenance(t, report)
	assertRemovedStaleArtifacts(t, report, stale)
	if report.DiagnosticCount == 0 {
		t.Fatal("diagnostic count = 0, want at least one")
	}
	if !hasDiagnosticCode(report.Diagnostics, "HZN2600") {
		t.Fatalf("report diagnostics = %#v, want HZN2600", report.Diagnostics)
	}
	assertSourceDetail(t, report, input)
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(report.Artifacts))
	}
	assertArtifactDetail(t, report, "diagnostics")
	if len(report.ArtifactDetails) != 1 {
		t.Fatalf("artifact details = %#v, want diagnostics only", report.ArtifactDetails)
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

func TestWorkbenchReportsEmitterDiagnostics(t *testing.T) {
	outDir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "bad.hzn")
	if err := os.WriteFile(sourcePath, []byte("package probes\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	result := &compiler.Result{
		Files: []compiler.FileResult{{Path: sourcePath, Package: "probes"}},
		Program: ir.Program{
			Package: "probes",
			Functions: []ir.Function{{
				Name:    "Bad",
				Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
				Body: []ir.Block{{
					Statements: []ir.Statement{{Kind: "while"}},
				}},
			}},
		},
	}

	report, err := writeWorkbenchArtifacts(result, workbenchOptions{OutDir: outDir})
	if err == nil {
		t.Fatal("writeWorkbenchArtifacts succeeded, want emitter error")
	}
	if report.Status != "emit_error" {
		t.Fatalf("status = %q, want emit_error", report.Status)
	}
	if report.DiagnosticCount != 1 || !hasDiagnosticCode(report.Diagnostics, "HZN3000") {
		t.Fatalf("diagnostics = %#v, want HZN3000", report.Diagnostics)
	}
	for _, name := range []string{
		"bad.diagnostics.json",
		"bad.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing emitter diagnostic artifact %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"bad.bpf.c",
		"bad.hznmap.json",
		"bad.bindings.go",
		"bad.cap.json",
		"bad.bpf.o",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); !os.IsNotExist(err) {
			t.Fatalf("generated artifact %s should not exist for emitter error: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "bad.diagnostics.json"))
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v", err)
	}
	if !hasDiagnosticCode(diagnostics, "HZN3000") {
		t.Fatalf("diagnostics artifact = %#v, want HZN3000", diagnostics)
	}
}

func TestWorkbenchReportsBindgenDiagnostics(t *testing.T) {
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "testdata", "golden", "exec", "input.hzn")
	stale := writeStaleArtifacts(t,
		filepath.Join(outDir, "input.bindings.go"),
		filepath.Join(outDir, "input.cap.json"),
		filepath.Join(outDir, "input.bpf.o"),
	)
	stdout, err := captureStdout(t, func() error {
		return run([]string{"workbench", input, "-o", outDir, "-package", "bad-name", "-json"})
	})
	if err == nil {
		t.Fatal("run workbench -package bad-name succeeded, want bindgen diagnostic error")
	}

	var report workbenchReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal stdout report: %v\n%s", err, stdout)
	}
	if report.Status != "bindgen_error" {
		t.Fatalf("status = %q, want bindgen_error", report.Status)
	}
	assertReportProvenance(t, report)
	assertRemovedStaleArtifacts(t, report, stale)
	if report.DiagnosticCount != 1 || !hasDiagnosticCode(report.Diagnostics, "HZN3200") {
		t.Fatalf("diagnostics = %#v, want HZN3200", report.Diagnostics)
	}
	for _, name := range []string{
		"input.bpf.c",
		"input.hznmap.json",
		"input.diagnostics.json",
		"input.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing bindgen failure artifact %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"input.bindings.go",
		"input.cap.json",
		"input.bpf.o",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); !os.IsNotExist(err) {
			t.Fatalf("downstream artifact %s should not exist for bindgen error: %v", name, err)
		}
	}
	for _, kind := range []string{"bpf_c", "source_map", "diagnostics"} {
		assertArtifactDetail(t, report, kind)
	}
	if _, ok := artifactDetailByKind(report.ArtifactDetails, "bindings"); ok {
		t.Fatalf("artifact details include bindings on bindgen error: %#v", report.ArtifactDetails)
	}
}

func TestWorkbenchReportsCapabilityDiagnostics(t *testing.T) {
	outDir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "badcap.hzn")
	if err := os.WriteFile(sourcePath, []byte("package probes\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	stale := writeStaleArtifacts(t,
		filepath.Join(outDir, "badcap.cap.json"),
		filepath.Join(outDir, "badcap.bpf.o"),
	)
	result := &compiler.Result{
		Files: []compiler.FileResult{{Path: sourcePath, Package: "probes"}},
		Program: ir.Program{
			Package: "probes",
			Functions: []ir.Function{{
				Name:    "OnExec",
				Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec", Attach: "sched:sched_process_exec"},
				Body: []ir.Block{{
					Statements: []ir.Statement{{Kind: "return", Value: &ir.Expr{Kind: "int", Value: "0"}}},
				}},
			}},
			Capabilities: []ir.Capability{{
				Name:    "kernel.process.exec.observe",
				Kind:    ir.CapabilitySource,
				Danger:  ir.DangerLevel("destroy"),
				Program: "OnExec",
				Section: "tracepoint/sched/sched_process_exec",
			}},
		},
	}

	report, err := writeWorkbenchArtifacts(result, workbenchOptions{OutDir: outDir})
	if err == nil {
		t.Fatal("writeWorkbenchArtifacts succeeded, want capability error")
	}
	if report.Status != "capability_error" {
		t.Fatalf("status = %q, want capability_error", report.Status)
	}
	assertReportProvenance(t, report)
	assertRemovedStaleArtifacts(t, report, stale)
	if report.DiagnosticCount != 1 || !hasDiagnosticCode(report.Diagnostics, "HZN3300") {
		t.Fatalf("diagnostics = %#v, want HZN3300", report.Diagnostics)
	}
	for _, name := range []string{
		"badcap.bpf.c",
		"badcap.hznmap.json",
		"badcap.bindings.go",
		"badcap.diagnostics.json",
		"badcap.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing capability failure artifact %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"badcap.cap.json",
		"badcap.bpf.o",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); !os.IsNotExist(err) {
			t.Fatalf("downstream artifact %s should not exist for capability error: %v", name, err)
		}
	}
	for _, kind := range []string{"bpf_c", "source_map", "bindings", "diagnostics"} {
		assertArtifactDetail(t, report, kind)
	}
	if _, ok := artifactDetailByKind(report.ArtifactDetails, "capabilities"); ok {
		t.Fatalf("artifact details include capabilities on capability error: %#v", report.ArtifactDetails)
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
	assertReportProvenance(t, report)
	assertRemovedStaleArtifacts(t, report, []string{filepath.Join(outDir, "input.bpf.o")})
	if report.Clang == "" {
		t.Fatal("clang output is empty")
	}
	if report.DiagnosticCount == 0 || !hasDiagnosticCode(report.Diagnostics, "HZN3100") {
		t.Fatalf("diagnostics = %#v, want HZN3100", report.Diagnostics)
	}
	if report.Diagnostics[0].Primary.File != "../../testdata/golden/exec/input.hzn" {
		t.Fatalf("primary file = %q, want authored input", report.Diagnostics[0].Primary.File)
	}
	assertSourceDetail(t, report, input)
	if artifactsContain(report.Artifacts, filepath.Join(outDir, "input.bpf.o")) {
		t.Fatalf("artifacts include missing object: %#v", report.Artifacts)
	}
	for _, kind := range []string{"bpf_c", "source_map", "bindings", "capabilities", "diagnostics"} {
		assertArtifactDetail(t, report, kind)
	}
	if _, ok := artifactDetailByKind(report.ArtifactDetails, "bpf_object"); ok {
		t.Fatalf("artifact details include missing object: %#v", report.ArtifactDetails)
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

func sourceDetailByPath(details []sourceDetail, path string) (sourceDetail, bool) {
	for _, detail := range details {
		if detail.Path == path {
			return detail, true
		}
	}
	return sourceDetail{}, false
}

func assertSourceDetail(t *testing.T, report workbenchReport, path string) {
	t.Helper()
	detail, ok := sourceDetailByPath(report.Sources, path)
	if !ok {
		t.Fatalf("sources missing %q: %#v", path, report.Sources)
	}
	if detail.Package == "" {
		t.Fatalf("source %s package is empty", path)
	}
	if detail.Size <= 0 {
		t.Fatalf("source %s size = %d, want positive", path, detail.Size)
	}
	if len(detail.SHA256) != 64 {
		t.Fatalf("source %s sha256 = %q, want 64 hex chars", path, detail.SHA256)
	}
	for _, ch := range detail.SHA256 {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			t.Fatalf("source %s sha256 = %q, want lowercase hex", path, detail.SHA256)
		}
	}
}

func assertReportProvenance(t *testing.T, report workbenchReport) {
	t.Helper()
	if report.Generator != "hzn workbench" {
		t.Fatalf("generator = %q, want hzn workbench", report.Generator)
	}
	if report.GeneratedAt == "" {
		t.Fatal("generated_at is empty")
	}
	ts, err := time.Parse(time.RFC3339, report.GeneratedAt)
	if err != nil {
		t.Fatalf("generated_at = %q, want RFC3339 timestamp: %v", report.GeneratedAt, err)
	}
	if ts.IsZero() {
		t.Fatalf("generated_at = %q, want non-zero timestamp", report.GeneratedAt)
	}
}

func assertRemovedStaleArtifacts(t *testing.T, report workbenchReport, paths []string) {
	t.Helper()
	if len(report.RemovedStaleArtifacts) != len(paths) {
		t.Fatalf("removed stale artifacts = %#v, want exactly %#v", report.RemovedStaleArtifacts, paths)
	}
	for _, path := range paths {
		if !artifactsContain(report.RemovedStaleArtifacts, path) {
			t.Fatalf("removed stale artifacts = %#v, missing %q", report.RemovedStaleArtifacts, path)
		}
	}
}

func writeStaleArtifacts(t *testing.T, paths ...string) []string {
	t.Helper()
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create artifact dir for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatalf("write stale artifact %s: %v", path, err)
		}
	}
	return paths
}

func artifactDetailByKind(details []artifactDetail, kind string) (artifactDetail, bool) {
	for _, detail := range details {
		if detail.Kind == kind {
			return detail, true
		}
	}
	return artifactDetail{}, false
}

func assertArtifactDetail(t *testing.T, report workbenchReport, kind string) {
	t.Helper()
	detail, ok := artifactDetailByKind(report.ArtifactDetails, kind)
	if !ok {
		t.Fatalf("artifact details missing %q: %#v", kind, report.ArtifactDetails)
	}
	if detail.Path == "" {
		t.Fatalf("%s path is empty", kind)
	}
	if detail.Size <= 0 {
		t.Fatalf("%s size = %d, want positive", kind, detail.Size)
	}
	if len(detail.SHA256) != 64 {
		t.Fatalf("%s sha256 = %q, want 64 hex chars", kind, detail.SHA256)
	}
	for _, ch := range detail.SHA256 {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			t.Fatalf("%s sha256 = %q, want lowercase hex", kind, detail.SHA256)
		}
	}
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
