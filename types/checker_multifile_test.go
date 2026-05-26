package types

import (
	"slices"
	"strings"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/parser"
)

func parseTestFileAt(t *testing.T, path, source string) ast.File {
	t.Helper()
	parsed, err := parser.ParseSource(parser.SourceFile{
		Path:   path,
		Bytes:  []byte(source),
		FileID: span.FileID(path),
	})
	if err != nil {
		t.Fatalf("ParseSource(%s): %v", path, err)
	}
	file, err := ast.Build(parsed)
	if err != nil {
		t.Fatalf("Build(%s): %v", path, err)
	}
	return *file
}

// TestRejectsDuplicateDeclAcrossFilesInPackage verifies that when two files in
// the same package declare a type with the same name, CheckPackage surfaces
// HZN1002 on the second declaration AND attributes the prior file path in the
// diagnostic notes. The enriched message lets users navigate to the first
// declaration even when the conflict spans files.
func TestRejectsDuplicateDeclAcrossFilesInPackage(t *testing.T) {
	a := parseTestFileAt(t, "a.hzn", `package probes

type Event struct {
    pid u32
}
`)
	b := parseTestFileAt(t, "b.hzn", `package probes

type Event struct {
    uid u32
}
`)

	all := CheckPackage([]ast.File{a, b})
	if len(all) != 2 {
		t.Fatalf("CheckPackage returned %d slices, want 2", len(all))
	}

	// The duplicate fires on the second file's declaration.
	bDiags := all[1]
	idx := slices.IndexFunc(bDiags, func(d diag.Diagnostic) bool { return d.Code == "HZN1002" })
	if idx < 0 {
		t.Fatalf("file b diagnostics = %#v, want HZN1002", bDiags)
	}
	got := bDiags[idx]

	hasFileNote := false
	for _, note := range got.Notes {
		if strings.Contains(note, "a.hzn") {
			hasFileNote = true
			break
		}
	}
	if !hasFileNote {
		t.Fatalf("HZN1002 notes = %#v, want a note referencing prior file \"a.hzn\"", got.Notes)
	}
}

// TestAllowsTypeDeclaredInOneFileUsedInAnother verifies that a type declared
// in one file is visible from another file in the same package — no
// diagnostic should fire when file B's function takes a pointer to a type
// declared in file A.
func TestAllowsTypeDeclaredInOneFileUsedInAnother(t *testing.T) {
	a := parseTestFileAt(t, "types.hzn", `package probes

type Event struct {
    pid u32
}
`)
	b := parseTestFileAt(t, "prog.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil { return 0 }
    event.pid = bpf.current_pid()
    Events.submit(event)
    return 0
}
`)

	all := CheckPackage([]ast.File{a, b})
	for i, d := range all {
		if diag.HasErrors(d) {
			t.Fatalf("file %d diagnostics = %#v, want no errors", i, d)
		}
	}
}

// TestMultiFileCapabilityAttribute verifies that @capability(X) in file B
// resolves to a `capability X` declared in file A.
func TestMultiFileCapabilityAttribute(t *testing.T) {
	a := parseTestFileAt(t, "caps.hzn", `package probes

capability ExecObserve danger observe = "kernel.process.exec.observe"
`)
	b := parseTestFileAt(t, "prog.hzn", `package probes

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)

	all := CheckPackage([]ast.File{a, b})
	for i, d := range all {
		if diag.HasErrors(d) {
			t.Fatalf("file %d diagnostics = %#v, want no errors", i, d)
		}
	}
}

// TestMultiFileMapReferencedFromOtherFile verifies that a map declared in
// file A is reachable from a function in file B.
func TestMultiFileMapReferencedFromOtherFile(t *testing.T) {
	a := parseTestFileAt(t, "maps.hzn", `package probes

map Counts hash[u32, u64]
`)
	b := parseTestFileAt(t, "prog.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    seen := Counts.lookup(pid)
    if seen == nil {
        return 0
    }
    return 0
}
`)

	all := CheckPackage([]ast.File{a, b})
	for i, d := range all {
		if diag.HasErrors(d) {
			t.Fatalf("file %d diagnostics = %#v, want no errors", i, d)
		}
	}
}
