package types_test

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/parser"
	"m31labs.dev/horizon/types"
)

func parseRegistryTestFile(t *testing.T, source string) ast.File {
	t.Helper()
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(source)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := ast.Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return *file
}

// TestRejectsUnknownAttachSurfaceAtParseTime verifies that a function annotated
// with a surface name not in the canonical registry (and not a known
// compiler-internal attribute) produces HZN1338 during the type-check pass,
// not at emit time via HZN3300.
func TestRejectsUnknownAttachSurfaceAtParseTime(t *testing.T) {
	file := parseRegistryTestFile(t, `package probes

@bogus_surface("foo")
func BadAttach(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	diags := types.Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1338" }) {
		t.Fatalf("diagnostics = %#v, want HZN1338 for unknown attach surface @bogus_surface", diags)
	}
}

// TestRejectsUnknownNamespacePrefixAtParseTime verifies that a capability
// declaration referencing a namespace prefix not present in the canonical
// registry produces HZN1339 during the type-check pass, not at emit time
// via HZN3300.
func TestRejectsUnknownNamespacePrefixAtParseTime(t *testing.T) {
	file := parseRegistryTestFile(t, `package probes

capability BadCap = "kernel.unknown.namespace.observe"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	diags := types.Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1339" }) {
		t.Fatalf("diagnostics = %#v, want HZN1339 for unknown namespace prefix kernel.unknown.namespace", diags)
	}
}
