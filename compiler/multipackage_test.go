package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

// TestAnalyzePathStillWorksWithoutImports regression-pins that wiring
// ResolveImports into AnalyzePath does not perturb the existing single-
// package path. The legacy `examples/execwatch/` build must still produce a
// non-error result with the same shape it did before #20 began.
func TestAnalyzePathStillWorksWithoutImports(t *testing.T) {
	result, err := AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("execwatch produced errors after ResolveImports wiring: %#v", result.Diagnostics)
	}
	if result.Program.Package != "probes" {
		t.Fatalf("Program.Package = %q, want probes", result.Program.Package)
	}
	if len(result.Program.Functions) != 1 {
		t.Fatalf("Functions = %d, want 1", len(result.Program.Functions))
	}
	if len(result.Program.Maps) != 1 {
		t.Fatalf("Maps = %d, want 1", len(result.Program.Maps))
	}
	if len(result.Program.Capabilities) != 1 {
		t.Fatalf("Capabilities = %d, want 1", len(result.Program.Capabilities))
	}
}

// TestAnalyzePathRejectsCrossPackageBuildForNow pins the interim error path:
// until Tasks 3/4 land the type-checker and IR-merge plumbing, a build that
// imports a non-builtin package must surface a clear diagnostic rather than
// silently dropping the import.
func TestAnalyzePathRejectsCrossPackageBuildForNow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.hzn"), []byte(`package main

import events "./events"

type Wrapper struct {
    a u32
}
`), 0o600); err != nil {
		t.Fatalf("write main: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o755); err != nil {
		t.Fatalf("mkdir events: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events", "events.hzn"), []byte(`package events

type ExecEvent struct {
    ts_ns u64
}
`), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if !diag.HasErrors(result.Diagnostics) {
		t.Fatalf("expected an error diagnostic for unsupported multi-package build, got %#v", result.Diagnostics)
	}
	found := false
	for _, d := range result.Diagnostics {
		if strings.Contains(d.Message, "cross-package builds not yet wired") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected diagnostic about cross-package builds, got %#v", result.Diagnostics)
	}
}

// TestAnalyzePathBuiltinOnlyImportsStillSinglePackage confirms that a build
// importing only compiler-builtin namespaces (bpf, xdp, etc.) continues to
// take the legacy single-package code path — builtins contribute no on-disk
// deps, so `len(deps) == 0` should hold.
func TestAnalyzePathBuiltinOnlyImportsStillSinglePackage(t *testing.T) {
	result, err := AnalyzePath("../examples/multifile-execcount")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("multifile-execcount produced errors: %#v", result.Diagnostics)
	}
	if result.Program.Package != "execcount" {
		t.Fatalf("Program.Package = %q, want execcount", result.Program.Package)
	}
}
