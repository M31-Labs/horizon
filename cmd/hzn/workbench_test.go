package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
	if len(report.Artifacts) != 5 {
		t.Fatalf("artifacts = %d, want 5", len(report.Artifacts))
	}
}
