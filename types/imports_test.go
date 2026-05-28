package types

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
)

// TestCompilerNamespaceWithUserAliases pins the alias-aware namespace check.
// Without aliases, the hardcoded compiler namespaces (bpf/xdp/...) are
// reserved. When an explicit user-package alias set is threaded through, an
// alias such as "events" is reported as a namespace (so it cannot be
// shadowed by a sibling top-level decl), but it must NOT collide with the
// HZN1004 compiler-namespace path because users declare their own aliases.
func TestCompilerNamespaceWithUserAliases(t *testing.T) {
	if !compilerNamespace("bpf") {
		t.Fatalf("compilerNamespace(\"bpf\") = false, want true (hardcoded namespace)")
	}
	if compilerNamespace("events") {
		t.Fatalf("compilerNamespace(\"events\") = true, want false (no aliases threaded)")
	}
	if !compilerNamespaceWithAliases("bpf", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"bpf\", {events}) = false, want true")
	}
	if !compilerNamespaceWithAliases("events", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"events\", {events}) = true requires alias awareness")
	}
	if compilerNamespaceWithAliases("other", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"other\", {events}) = true, want false")
	}
}

// TestDeclareNameAllowsUserPackageAlias verifies the additive integration:
// declarePackageName, when threaded an alias set, treats user-package aliases
// as a reserved namespace WITHOUT firing the HZN1004 compiler-namespace
// collision diagnostic. The collision case for user aliases is reserved for
// a separate diagnostic in subsequent subtasks; this test only pins that
// HZN1004 does not fire for them.
func TestDeclareNameAllowsUserPackageAlias(t *testing.T) {
	env := NewEnv()
	var diags []diag.Diagnostic
	decl := stubDeclRef{span: span.Span{File: "a.hzn"}}
	ok := declarePackageNameWithAliases(&diags, env, "events", decl, map[string]bool{"events": true})
	if ok {
		t.Fatalf("declarePackageNameWithAliases returned true; want false because the alias \"events\" reserves the name")
	}
	if idx := slices.IndexFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1004" }); idx >= 0 {
		t.Fatalf("user-package alias must NOT trigger HZN1004; got %#v", diags[idx])
	}
}

type stubDeclRef struct {
	span span.Span
}

func (s stubDeclRef) GetSpan() span.Span { return s.span }

// satisfy ast.Decl is not required — DeclRef only requires GetSpan.
var _ DeclRef = stubDeclRef{}
var _ = ast.File{}

// parseTestPackage parses an in-memory map of fileName → source into an
// ast.Package suitable for CheckPackages. Files are sorted by name so order
// is deterministic across runs.
func parseTestPackage(t *testing.T, dir, pkgName string, sources map[string]string) ast.Package {
	t.Helper()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	slices.Sort(names)
	pkg := ast.Package{Name: pkgName}
	for _, name := range names {
		file := parseTestFileAt(t, dir+"/"+name, sources[name])
		if pkg.Name == "" {
			pkg.Name = file.Package
		}
		pkg.Files = append(pkg.Files, file)
	}
	return pkg
}

// TestCheckPackageWrapsCheckPackages pins the backward-compatible thin
// wrapper: CheckPackage([]ast.File) must produce the same per-file
// diagnostics as routing the same files through CheckPackages with an empty
// graph. This guarantees existing single-package callers continue to work
// unchanged after Subtask 3b lands the new entrypoint.
func TestCheckPackageWrapsCheckPackages(t *testing.T) {
	file := parseTestFileAt(t, "a.hzn", `package probes

type Event struct {
    pid u32
}
`)
	got := CheckPackage([]ast.File{file})
	if len(got) != 1 {
		t.Fatalf("CheckPackage returned %d slices, want 1", len(got))
	}
	if len(got[0]) != 0 {
		t.Fatalf("CheckPackage diagnostics = %#v, want none", got[0])
	}
}

// TestSelectorTypeResolvesToImportedStruct verifies the happy path of
// qualified selector-type lookup: a root package can reference a struct
// defined in an imported package via `<alias>.<TypeName>` and the type
// checker resolves it without emitting HZN1102.
func TestSelectorTypeResolvesToImportedStruct(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

map Events ringbuf[events.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":      root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	rootDiags := results["/root"]
	for _, perFile := range rootDiags {
		for _, d := range perFile {
			if d.Severity == diag.SeverityError {
				t.Fatalf("unexpected error in root package: %#v", d)
			}
		}
	}
}

// TestSelectorTypeRejectsUnknownPackageAlias fires HZN1557 when a
// selector-type references an alias that was never imported.
func TestSelectorTypeRejectsUnknownPackageAlias(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"

map Events ringbuf[unknown.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {"bpf": "m31labs.dev/horizon/runtime/kernel"},
		},
		Packages:       map[string]ast.Package{"/root": root},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root}, graph)
	if !hasDiagCode(results["/root"], "HZN1557") {
		t.Fatalf("expected HZN1557 for unknown import alias; got %#v", results["/root"])
	}
}

// TestSelectorTypeRejectsUnknownStructInImportedPackage fires HZN1558 when
// the alias resolves but the named struct does not exist in the imported
// package.
func TestSelectorTypeRejectsUnknownStructInImportedPackage(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

map Events ringbuf[events.MissingEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":      root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1558") {
		t.Fatalf("expected HZN1558 for unknown struct in imported package; got %#v", results["/root"])
	}
}

func hasDiagCode(perFile [][]diag.Diagnostic, code string) bool {
	for _, fileDiags := range perFile {
		if slices.IndexFunc(fileDiags, func(d diag.Diagnostic) bool { return d.Code == code }) >= 0 {
			return true
		}
	}
	return false
}

// TestQualifiedLookupRejectsLowercaseType pins the v0.3 privacy gate
// (roadmap #17): a qualified type reference to a lowercase symbol in an
// imported package is rejected with HZN1670. The companion uppercase test
// just below pins the negative — no HZN1670 fires when the symbol is
// already exported.
func TestQualifiedLookupRejectsLowercaseType(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

map Events ringbuf[events.execEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type execEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1670") {
		t.Fatalf("expected HZN1670 for lowercase qualified type reference; got %#v", results["/root"])
	}
}

// TestQualifiedLookupAcceptsUppercaseType pins the negative side of #17:
// an uppercase qualified type reference must NOT trip the privacy gate.
func TestQualifiedLookupAcceptsUppercaseType(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

map Events ringbuf[events.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if hasDiagCode(results["/root"], "HZN1670") {
		t.Fatalf("HZN1670 fired for uppercase qualified type reference; got %#v", results["/root"])
	}
}

// TestQualifiedLookupRejectsLowercaseFunc pins #17 for qualified function
// calls: `events.helper()` produces HZN1671. The current language does not
// resolve cross-package func calls positively (that arrives with #15
// re-exports), so the privacy gate is the only diagnostic surfacing here —
// and it must surface with the specific HZN1671 code, not a generic fallback.
func TestQualifiedLookupRejectsLowercaseFunc(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    events.helper()
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

func helper() i32 {
    return 0
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1671") {
		t.Fatalf("expected HZN1671 for lowercase qualified function call; got %#v", results["/root"])
	}
}

// TestQualifiedLookupRejectsLowercaseMap pins #17 for qualified map
// references: `events.events.lookup(...)` (where the imported map is
// lowercase) produces HZN1672.
func TestQualifiedLookupRejectsLowercaseMap(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    events.events.lookup(0)
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

map events hash[u32]u64
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1672") {
		t.Fatalf("expected HZN1672 for lowercase qualified map reference; got %#v", results["/root"])
	}
}

// TestQualifiedLookupRejectsLowercaseCapAttribute pins #17 for capability
// attribute references: `@capability(events.execobserve)` produces HZN1673.
func TestQualifiedLookupRejectsLowercaseCapAttribute(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

@capability(events.execobserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

capability execobserve danger observe = "kernel.process.exec.observe"
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1673") {
		t.Fatalf("expected HZN1673 for lowercase qualified capability attribute reference; got %#v", results["/root"])
	}
}

// TestQualifiedLookupRejectsLowercaseConst pins #17 for qualified const
// references: `events.threshold` (where the imported const is lowercase)
// produces HZN1674.
func TestQualifiedLookupRejectsLowercaseConst(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    x := events.threshold
    return x
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

const threshold i32 = 42
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":       root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	if !hasDiagCode(results["/root"], "HZN1674") {
		t.Fatalf("expected HZN1674 for lowercase qualified const reference; got %#v", results["/root"])
	}
}

// TestQualifiedLookupAllowsSamePackageLowercase pins the intra-package
// negative: privacy is a cross-package gate only — a same-package reference
// to a lowercase symbol stays legal. The fixture declares a lowercase
// helper and calls it from a sibling file in the same package; no HZN1671
// must fire.
func TestQualifiedLookupAllowsSamePackageLowercase(t *testing.T) {
	pkg := parseTestPackage(t, "/root", "main", map[string]string{
		"a.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"

func helper() i32 {
    return 0
}
`,
		"b.hzn": `package main

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return helper()
}
`,
	})
	graph := ImportGraph{
		Edges:          map[string]map[string]string{"/root": {"bpf": "m31labs.dev/horizon/runtime/kernel"}},
		Packages:       map[string]ast.Package{"/root": pkg},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{pkg}, graph)
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Code == "HZN1670" || d.Code == "HZN1671" || d.Code == "HZN1672" || d.Code == "HZN1673" || d.Code == "HZN1674" {
				t.Fatalf("intra-package lowercase reference must not trip privacy gates; got %#v", d)
			}
		}
	}
}

// TestCapabilityAttributeAcceptsQualifiedReference verifies the Subtask 3c
// shape: `@capability(events.ExecObserve)` parses and resolves through
// CheckPackages when ExecObserve is declared in the imported `events`
// package. The test pins that HZN1321 (unknown alias) does NOT fire and
// that no parse or type-check error mentions the attribute.
func TestCapabilityAttributeAcceptsQualifiedReference(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import events "m31labs.dev/horizon-test/events"

@capability(events.ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	dep := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

capability ExecObserve danger observe = "kernel.process.exec.observe"
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf":    "m31labs.dev/horizon/runtime/kernel",
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":      root,
			"/dep/events": dep,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, dep}, graph)
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Code == "HZN1321" || d.Code == "HZN1302" || d.Code == "HZN1404" {
				t.Fatalf("qualified @capability reference rejected: %#v", d)
			}
			if d.Severity == diag.SeverityError {
				t.Fatalf("unexpected error: %#v", d)
			}
		}
	}
}
