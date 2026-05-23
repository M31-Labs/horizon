package compiler_test

import (
	"encoding/json"
	"testing"

	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/emitc"
	"m31labs.dev/horizon/internal/testutil"
)

func TestExecGoldenArtifacts(t *testing.T) {
	result, err := compiler.AnalyzePath("../testdata/golden/exec/input.hzn")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}

	cOutput, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	compareGolden(t, "../testdata/golden/exec/output.bpf.c", cOutput.Code)

	bindings, err := bindgen.Generate(result.Program, "bindings")
	if err != nil {
		t.Fatalf("Generate bindings: %v", err)
	}
	compareGolden(t, "../testdata/golden/exec/output.bindings.go", bindings)

	manifest := capability.FromIR(result.Program)
	if err := capability.Validate(manifest); err != nil {
		t.Fatalf("Validate manifest: %v", err)
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	compareGolden(t, "../testdata/golden/exec/output.cap.json", string(append(manifestJSON, '\n')))
}

func compareGolden(t *testing.T, path string, got string) {
	t.Helper()
	want := testutil.ReadGolden(t, path)
	got = testutil.NormalizeGolden(got)
	want = testutil.NormalizeGolden(want)
	if got != want {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
