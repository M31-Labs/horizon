package compiler

import (
	"os"
	"path/filepath"
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

// TestAnalyzePathTwoPackageBuild verifies the cross-package build wiring
// introduced in Phase 2 Subtask 4b: a root package importing a sibling
// events package type-checks and lowers cleanly, and the resulting IR
// program carries decls from both packages with Origin populated only on
// the dependency's decls. The events package contributes:
//   - ExecEvent struct (referenced from main via events.ExecEvent in a map)
//   - MaxBufSize const (referenced from main via events.MaxBufSize as the
//     map's max_entries — this exercises the package-aware
//     resolveMapMaxEntries path)
//
// The root package main contributes the entrypoint OnExec, the ringbuf
// Events, and the ExecObserve capability.
func TestAnalyzePathTwoPackageBuild(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o755); err != nil {
		t.Fatalf("mkdir events: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events", "events.hzn"), []byte(`package events

type ExecEvent struct {
    ts_ns u64
    pid u32
}

const MaxBufSize u32 = 4096
`), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.hzn"), []byte(`package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "./events"

@max_entries(events.MaxBufSize)
map Events ringbuf[events.ExecEvent]

capability ExecObserve danger observe = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil { return 0 }
    event.ts_ns = bpf.ktime_get_ns()
    event.pid = bpf.current_pid()
    Events.submit(event)
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("write main: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("two-package build produced errors: %#v", result.Diagnostics)
	}
	if result.Program.Package != "main" {
		t.Fatalf("Program.Package = %q, want main", result.Program.Package)
	}

	var depStruct, rootMap bool
	for _, s := range result.Program.Structs {
		if s.Name == "ExecEvent" && s.Origin == "events" {
			depStruct = true
		}
	}
	for _, m := range result.Program.Maps {
		if m.Name == "Events" {
			if m.Origin != "" {
				t.Errorf("root map Events Origin = %q, want empty", m.Origin)
			}
			if m.MaxEntries != "4096" {
				t.Errorf("Events.MaxEntries = %q, want 4096 (cross-package const resolution)", m.MaxEntries)
			}
			rootMap = true
		}
	}
	if !depStruct {
		t.Errorf("expected ExecEvent struct with Origin=events in merged IR; got structs %+v", result.Program.Structs)
	}
	if !rootMap {
		t.Errorf("expected root map Events in merged IR; got maps %+v", result.Program.Maps)
	}
	if len(result.Program.Functions) == 0 {
		t.Errorf("expected root function OnExec in merged IR; got %+v", result.Program.Functions)
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
