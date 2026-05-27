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
	// Pre-v0.3: clang-rooted diagnostics fell back to HZN3100 (the
	// verifier no-match sentinel) because the verifier-catalog gate
	// skipped clang origin. v0.3 (#13) routes clang diagnostics through
	// the clang catalog instead; an unrecognised clang warning lands on
	// HZN3400 — the clang-catalog no-match sentinel.
	if diagnostics[0].Code != "HZN3400" {
		t.Fatalf("code = %q, want HZN3400 (clang-catalog no-match sentinel)", diagnostics[0].Code)
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
	// The log shape `; bad_access();\ninvalid mem access 'scalar'` is
	// verifier-rooted (a C-source marker line followed by a verifier
	// diagnostic), so the Task 5.4 origin gate lets VC0001 (HZN3110)
	// match. The rendered remediation contains "nil guard"; the original
	// pre-catalog "nil-check" string came from the legacy
	// legacy suggestion switch and no longer applies — catalog
	// remediation is the contract for verifier-rooted diagnostics.
	if !strings.Contains(diagnostics[0].Suggest, "nil guard") {
		t.Fatalf("suggest = %q, want VC0001 nil-guard remediation", diagnostics[0].Suggest)
	}
	if diagnostics[0].Source == nil || diagnostics[0].Source.Line != 7 || !strings.Contains(diagnostics[0].Source.Text, "bad_access") {
		t.Fatalf("source context = %#v, want authored source line", diagnostics[0].Source)
	}
	if !hasNoteContaining(diagnostics[0], "0: R1=ctx() R10=fp0") || !hasNoteContaining(diagnostics[0], "; bad_access();") {
		t.Fatalf("notes = %#v, want verifier context", diagnostics[0].Notes)
	}
	generatedSource := generatedBPFLabelSource(diagnostics[0])
	if generatedSource == nil || !strings.Contains(generatedSource.Text, "bad_access();") || generatedSource.Marker == "" {
		t.Fatalf("generated source context = %#v, want generated BPF C line", generatedSource)
	}
}

func TestDiagnoseTextIncludesGeneratedSourceContext(t *testing.T) {
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
		return run([]string{"diagnose", logPath, "-map", mapPath})
	})
	if err != nil {
		t.Fatalf("run diagnose: %v", err)
	}
	if !strings.Contains(stdout, "generated: input.bpf.c:2:1") || !strings.Contains(stdout, "bad_access();") {
		t.Fatalf("stdout missing generated source context:\n%s", stdout)
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
	// See TestDiagnoseLoadsGeneratedSourceBesideSourceMap: this log is
	// verifier-rooted (the leading `;` source-marker line precedes the
	// verifier diagnostic), so the Task 5.4 origin gate passes the
	// lookup through and VC0001 matches; the remediation contains "nil
	// guard". A purely clang-shaped log carrying the same substring is
	// covered by TestDiagnoseSkipsCatalogForClangDiagnostics.
	if !strings.Contains(diagnostics[0].Suggest, "nil guard") {
		t.Fatalf("suggest = %q, want VC0001 nil-guard remediation", diagnostics[0].Suggest)
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
	if got, want := diagnostics[0].Primary.Start.Line, 27; got != want {
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
	if got, want := diagnostics[0].Primary.Start.Line, 14; got != want {
		t.Fatalf("primary line = %d, want %d; diagnostic = %#v", got, want, diagnostics[0])
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "cgroup.dst_port") {
		t.Fatalf("source context = %#v, want authored cgroup helper call", diagnostics[0].Source)
	}
	if !hasNoteContaining(diagnostics[0], "source map: function BlockSMTP, section cgroup/connect4, node cgroup_context_wrapper") {
		t.Fatalf("notes = %#v, want cgroup wrapper source map metadata", diagnostics[0].Notes)
	}
}

func TestDiagnoseMapsMapWrapperDiagnosticToAuthoredCall(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "count.bpf.c")
	mapPath := filepath.Join(dir, "count.hznmap.json")
	logPath := filepath.Join(dir, "clang.log")

	result, err := compiler.AnalyzePath("../../examples/execcount")
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
	line := diagnoseLineContaining(t, out.Code, "return bpf_map_lookup_elem(&ExecCounts, &key);")
	if err := os.WriteFile(logPath, []byte(fmt.Sprintf("%s:%d:12: error: call to undeclared function 'bpf_map_lookup_elem'\n", cPath, line)), 0o644); err != nil {
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
	if got, want := diagnostics[0].Primary.Start.Line, 21; got != want {
		t.Fatalf("primary line = %d, want %d; diagnostic = %#v", got, want, diagnostics[0])
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "ExecCounts.lookup") {
		t.Fatalf("source context = %#v, want authored map helper call", diagnostics[0].Source)
	}
	if !hasNoteContaining(diagnostics[0], "source map: function OnExec, section tracepoint/sched/sched_process_exec, node map_wrapper") {
		t.Fatalf("notes = %#v, want map wrapper source map metadata", diagnostics[0].Notes)
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

// TestDiagnoseAddsVerifierSpecificSuggestions was the legacy hand-coded
// legacy suggestion switch's table-driven coverage. The catalog now owns
// per-entry remediation, and the synthetic fixture corpus under
// testdata/verifier-fixtures/ exercised by verifier.TestVerifierCatalogFixtures
// asserts the full diagnostic shape per entry (not just a substring on
// .Suggest). The substring assertion this test enforced is strictly weaker
// than the fixture-snapshot coverage, so the test was removed in favour of
// the fixture harness. See roadmap #14 and the v0.2 phase-2 pine plan.

// TestDiagnoseUsesCatalogForKnownVerifierMessage pins the diagnose path's
// catalog enrichment: a known verifier message must produce the catalog
// entry's HZN code, render the catalog remediation into .Suggest, and
// surface the catalog id as a `verifier-catalog: <id>` note.
func TestDiagnoseUsesCatalogForKnownVerifierMessage(t *testing.T) {
	raw := "R2 invalid mem access 'scalar'"
	diagnostics := diagnosticsFromVerifierLog(raw, ir.SourceMap{}, nil)
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Code != "HZN3110" {
		t.Fatalf("code = %q, want HZN3110 (VC0001)", diagnostics[0].Code)
	}
	if !strings.Contains(diagnostics[0].Suggest, "nil guard") {
		t.Fatalf("suggest = %q, want VC0001 remediation substring (e.g. \"nil guard\")", diagnostics[0].Suggest)
	}
	if !hasNoteContaining(diagnostics[0], "verifier-catalog: VC0001") {
		t.Fatalf("notes = %#v, want note containing \"verifier-catalog: VC0001\"", diagnostics[0].Notes)
	}
}

// TestDiagnoseSkipsCatalogForClangDiagnostics pins the clang/verifier
// origin gate (Task 5.4): a clang-shaped diagnostic whose message text
// happens to overlap with a verifier-catalog regex (here, VC0001's
// `invalid mem access 'scalar'`) must NOT pick up the catalog's HZN31xx
// code or remediation. Clang and verifier are different vocabularies;
// the catalog targets the verifier only. Without the gate, catalog
// lookup is content-based and leaks verifier remediation into clang
// errors (the misclassification surfaced during Wave 3 — see plan
// Task 5.4).
func TestDiagnoseSkipsVerifierCatalogForClangDiagnostics(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "clang.log")
	// A clang-shaped diagnostic line. The message intentionally contains
	// the substring "invalid mem access 'scalar'" so that, sans the
	// origin gate, VC0001's regex would match against the clang error.
	// The clang catalog has no pattern for this text, so the diagnostic
	// lands on the clang no-match sentinel HZN3400 — proving the
	// verifier catalog did not leak across the gate (no `verifier-catalog:`
	// note) and the clang catalog did not silently misclassify it (no
	// `clang-catalog:` note either).
	clangLine := fmt.Sprintf("%s/some.bpf.c:17:9: error: invalid mem access 'scalar' in synthetic clang fixture\n", dir)
	if err := os.WriteFile(logPath, []byte(clangLine), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	// Pre-v0.3: clang origin landed on HZN3100 (verifier no-match
	// sentinel) because the verifier-catalog gate skipped it. v0.3 (#13):
	// clang origin lands on HZN3400 (clang no-match sentinel) — the
	// origin-gate invariant is preserved (no verifier leak) and the new
	// sentinel makes the origin explicit.
	if diagnostics[0].Code != "HZN3400" {
		t.Fatalf("code = %q, want HZN3400 (clang-catalog no-match sentinel)", diagnostics[0].Code)
	}
	if diagnostics[0].Suggest != "" {
		t.Fatalf("suggest = %q, want empty (no catalog match)", diagnostics[0].Suggest)
	}
	for _, note := range diagnostics[0].Notes {
		if strings.Contains(note, "verifier-catalog:") {
			t.Fatalf("notes contain verifier-catalog id on clang origin: %#v", diagnostics[0].Notes)
		}
		if strings.Contains(note, "clang-catalog:") {
			t.Fatalf("notes contain clang-catalog id on no-match path: %#v", diagnostics[0].Notes)
		}
	}
}

// TestDiagnoseUsesClangCatalogForKnownClangMessage pins the v0.3 #13
// contract: a clang-rooted diagnostic whose text matches a clang
// catalog entry is enriched with the catalog's HZN34xx code, a
// `clang-catalog: <id>` note, and the templated remediation. Mirrors
// the verifier-catalog enrichment test from pine's v0.2 work.
func TestDiagnoseUsesClangCatalogForKnownClangMessage(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "clang.log")
	clangLine := fmt.Sprintf("%s/some.bpf.c:17:9: error: use of undeclared identifier 'bpf_get_current_pid_tgid'\n", dir)
	if err := os.WriteFile(logPath, []byte(clangLine), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	// CC0001 (bpf-prefixed undeclared identifier) → HZN3410. Document
	// order in the catalog puts CC0001 before CC0002 (per O-8) so the
	// bpf-specific entry wins against the generic-undeclared entry.
	if diagnostics[0].Code != "HZN3410" {
		t.Fatalf("code = %q, want HZN3410 (CC0001)", diagnostics[0].Code)
	}
	if diagnostics[0].Suggest == "" {
		t.Fatalf("suggest is empty, want CC0001 remediation")
	}
	if !strings.Contains(diagnostics[0].Suggest, "runtime/horizon_bpf.h") {
		t.Fatalf("suggest = %q, want CC0001 remediation mentioning runtime/horizon_bpf.h", diagnostics[0].Suggest)
	}
	if !strings.Contains(diagnostics[0].Suggest, "vmlinux.h") {
		t.Fatalf("suggest = %q, want CC0001 remediation mentioning vmlinux.h", diagnostics[0].Suggest)
	}
	if !hasNoteContaining(diagnostics[0], "clang-catalog: CC0001") {
		t.Fatalf("notes = %#v, want `clang-catalog: CC0001` note", diagnostics[0].Notes)
	}
	if !hasNoteContaining(diagnostics[0], "capture: identifier=bpf_get_current_pid_tgid") {
		t.Fatalf("notes = %#v, want captured identifier note", diagnostics[0].Notes)
	}
	for _, note := range diagnostics[0].Notes {
		if strings.Contains(note, "verifier-catalog:") {
			t.Fatalf("notes contain verifier-catalog id on clang-rooted diagnostic: %#v", diagnostics[0].Notes)
		}
	}
}

// TestDiagnoseFallsBackToClangCatalogNoMatchSentinel pins the no-match
// contract: a clang-rooted diagnostic that matches no clang catalog
// entry must fall back to HZN3400 with empty Suggest and no
// `clang-catalog:` note.
func TestDiagnoseFallsBackToClangCatalogNoMatchSentinel(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "clang.log")
	// Chosen so it does not match any catalog entry (no `undeclared
	// identifier`, no `implicit declaration`, no `unknown type`, no
	// syntax / incompatible-types markers).
	clangLine := fmt.Sprintf("%s/some.bpf.c:1:1: error: completely chaotic clang message that no catalog entry matches\n", dir)
	if err := os.WriteFile(logPath, []byte(clangLine), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	stdout, err := captureStdout(t, func() error {
		return run([]string{"diagnose", logPath, "-json"})
	})
	if err != nil {
		t.Fatalf("run diagnose: %v", err)
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Code != "HZN3400" {
		t.Fatalf("code = %q, want HZN3400 (clang-catalog no-match sentinel)", diagnostics[0].Code)
	}
	if diagnostics[0].Suggest != "" {
		t.Fatalf("suggest = %q, want empty for clang no-match", diagnostics[0].Suggest)
	}
	for _, note := range diagnostics[0].Notes {
		if strings.Contains(note, "clang-catalog:") {
			t.Fatalf("notes contain clang-catalog id on no-match path: %#v", diagnostics[0].Notes)
		}
	}
}

// TestDiagnoseFallsBackToHZN3100WhenCatalogDoesNotMatch pins the no-match
// contract: a verifier message that does not match any catalog entry must
// fall back to HZN3100 with an empty Suggest and no `verifier-catalog:` note
// (no stale heuristic, no misleading remediation).
func TestDiagnoseFallsBackToHZN3100WhenCatalogDoesNotMatch(t *testing.T) {
	raw := "verifier failed: completely unrelated chaos"
	diagnostics := diagnosticsFromVerifierLog(raw, ir.SourceMap{}, nil)
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Code != "HZN3100" {
		t.Fatalf("code = %q, want HZN3100 (no catalog match)", diagnostics[0].Code)
	}
	if diagnostics[0].Suggest != "" {
		t.Fatalf("suggest = %q, want empty for no-catalog-match path", diagnostics[0].Suggest)
	}
	for _, note := range diagnostics[0].Notes {
		if strings.Contains(note, "verifier-catalog:") {
			t.Fatalf("notes contain catalog id on no-match path: %#v", diagnostics[0].Notes)
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

func generatedBPFLabelSource(diagnostic diag.Diagnostic) *diag.Source {
	for _, label := range diagnostic.Labels {
		if label.Message == "generated BPF C" {
			return label.Source
		}
	}
	return nil
}
