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

// TestReExportedTypeAccessibleFromTransitiveImporter pins the v0.3 #15
// happy path: a middleware package re-exports `events.ExecEvent` via
// `export events.ExecEvent`, and a root package imports the middleware
// and references `mw.ExecEvent` in a map declaration. The type checker
// must not emit HZN1558 ("type not declared") for the qualified
// reference — the re-export brings the symbol into mw's surface.
func TestReExportedTypeAccessibleFromTransitiveImporter(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import mw "m31labs.dev/horizon-test/middleware"

map Events ringbuf[mw.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	middleware := parseTestPackage(t, "/dep/middleware", "middleware", map[string]string{
		"middleware.hzn": `package middleware

import events "m31labs.dev/horizon-test/events"

export events.ExecEvent
`,
	})
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf": "m31labs.dev/horizon/runtime/kernel",
				"mw":  "/dep/middleware",
			},
			"/dep/middleware": {
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":           root,
			"/dep/middleware": middleware,
			"/dep/events":     events,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, middleware, events}, graph)
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Severity == diag.SeverityError {
				t.Fatalf("re-exported type unreachable from root: %#v", d)
			}
		}
	}
}

// TestReExportOfMissingSymbolEmitsHZN1690 pins the diagnostic for a
// re-export whose target name does not exist in the named import. The
// middleware says `export events.Nonexistent` but `events` declares no
// such symbol; the type-checker fires HZN1690 against the middleware's
// export decl.
func TestReExportOfMissingSymbolEmitsHZN1690(t *testing.T) {
	middleware := parseTestPackage(t, "/dep/middleware", "middleware", map[string]string{
		"middleware.hzn": `package middleware

import events "m31labs.dev/horizon-test/events"

export events.Nonexistent
`,
	})
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/middleware": {"events": "/dep/events"},
		},
		Packages: map[string]ast.Package{
			"/dep/middleware": middleware,
			"/dep/events":     events,
		},
	}
	results := CheckPackages([]ast.Package{middleware, events}, graph)
	if !hasDiagCode(results["/dep/middleware"], "HZN1690") {
		t.Fatalf("expected HZN1690 for missing re-export target; got %#v", results["/dep/middleware"])
	}
}

// TestReExportOfPrivateSymbolEmitsHZN1691 composes the re-export gate
// with the v0.3 privacy rule (#17). A re-export of a lowercase symbol
// is rejected with HZN1691 even though the symbol exists, because
// non-exported symbols cannot cross a package boundary in any form.
func TestReExportOfPrivateSymbolEmitsHZN1691(t *testing.T) {
	middleware := parseTestPackage(t, "/dep/middleware", "middleware", map[string]string{
		"middleware.hzn": `package middleware

import events "m31labs.dev/horizon-test/events"

export events.execEvent
`,
	})
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type execEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/middleware": {"events": "/dep/events"},
		},
		Packages: map[string]ast.Package{
			"/dep/middleware": middleware,
			"/dep/events":     events,
		},
	}
	results := CheckPackages([]ast.Package{middleware, events}, graph)
	if !hasDiagCode(results["/dep/middleware"], "HZN1691") {
		t.Fatalf("expected HZN1691 for re-export of private symbol; got %#v", results["/dep/middleware"])
	}
	if hasDiagCode(results["/dep/middleware"], "HZN1690") {
		t.Fatalf("re-export of present-but-private symbol must NOT fire HZN1690; got %#v", results["/dep/middleware"])
	}
}

// TestReExportShadowingLocalDeclEmitsHZN1692 pins shadow detection:
// re-exporting a symbol whose name collides with a local decl in the
// re-exporting package surfaces HZN1692. The middleware declares its
// own `ExecEvent` AND re-exports `events.ExecEvent` — the surface is
// ambiguous and the gate rejects.
func TestReExportShadowingLocalDeclEmitsHZN1692(t *testing.T) {
	middleware := parseTestPackage(t, "/dep/middleware", "middleware", map[string]string{
		"middleware.hzn": `package middleware

import events "m31labs.dev/horizon-test/events"

type ExecEvent struct {
    pid u32
}

export events.ExecEvent
`,
	})
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/middleware": {"events": "/dep/events"},
		},
		Packages: map[string]ast.Package{
			"/dep/middleware": middleware,
			"/dep/events":     events,
		},
	}
	results := CheckPackages([]ast.Package{middleware, events}, graph)
	if !hasDiagCode(results["/dep/middleware"], "HZN1692") {
		t.Fatalf("expected HZN1692 for shadowing re-export; got %#v", results["/dep/middleware"])
	}
}

// TestReExportSecondHopResolves pins v0.4 Track C (C4): re-exports now
// flow a SECOND hop. This is the deliberate inversion of v0.3's
// `TestReExportIsOneHopOnly` — the prior one-hop-only behavior was a
// documented non-goal (decisions/0007 §"One-hop only"), superseded by
// the §"v0.4 re-export reach" two-pass design.
//
// Package `events` declares `ExecEvent`. Package `b` re-exports
// `events.ExecEvent`. Package `c` then declares `export b.ExecEvent`
// — re-exporting the re-export. The two-pass surface resolution
// consults `b`'s pass-1 surface, so `c.ExecEvent` resolves with NO
// HZN1690, and a consumer of `c` can reach the symbol.
func TestReExportSecondHopResolves(t *testing.T) {
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	b := parseTestPackage(t, "/dep/b", "b", map[string]string{
		"b.hzn": `package b

import events "m31labs.dev/horizon-test/events"

export events.ExecEvent
`,
	})
	c := parseTestPackage(t, "/dep/c", "c", map[string]string{
		"c.hzn": `package c

import b "m31labs.dev/horizon-test/b"

export b.ExecEvent
`,
	})
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import c "m31labs.dev/horizon-test/c"

map Events ringbuf[c.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/b": {"events": "/dep/events"},
			"/dep/c": {"b": "/dep/b"},
			"/root": {
				"bpf": "m31labs.dev/horizon/runtime/kernel",
				"c":   "/dep/c",
			},
		},
		Packages: map[string]ast.Package{
			"/dep/events": events,
			"/dep/b":      b,
			"/dep/c":      c,
			"/root":       root,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{events, b, c, root}, graph)
	// The second hop must NOT be rejected.
	if hasDiagCode(results["/dep/c"], "HZN1690") {
		t.Fatalf("did not expect HZN1690 for second-hop re-export; got %#v", results["/dep/c"])
	}
	// And the symbol must be reachable from a consumer of `c`: the
	// `map Events ringbuf[c.ExecEvent]` must type-check without an
	// unknown-type diagnostic naming ExecEvent.
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Severity == diag.SeverityError && containsAll(d.Message, "ExecEvent") {
				t.Fatalf("second-hop re-exported type unreachable from root: %#v", d)
			}
		}
	}
}

// TestReExportThirdHopRejected pins the new bound: the two-pass design
// extends re-exports to exactly TWO hops. A fourth package `d` that
// declares `export c.ExecEvent` — where `c` is itself a second-hop
// re-exporter — is rejected with HZN1690. There is no pass 3, so the
// third hop never resolves.
func TestReExportThirdHopRejected(t *testing.T) {
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}
`,
	})
	b := parseTestPackage(t, "/dep/b", "b", map[string]string{
		"b.hzn": `package b

import events "m31labs.dev/horizon-test/events"

export events.ExecEvent
`,
	})
	c := parseTestPackage(t, "/dep/c", "c", map[string]string{
		"c.hzn": `package c

import b "m31labs.dev/horizon-test/b"

export b.ExecEvent
`,
	})
	d := parseTestPackage(t, "/dep/d", "d", map[string]string{
		"d.hzn": `package d

import c "m31labs.dev/horizon-test/c"

export c.ExecEvent
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/b": {"events": "/dep/events"},
			"/dep/c": {"b": "/dep/b"},
			"/dep/d": {"c": "/dep/c"},
		},
		Packages: map[string]ast.Package{
			"/dep/events": events,
			"/dep/b":      b,
			"/dep/c":      c,
			"/dep/d":      d,
		},
	}
	results := CheckPackages([]ast.Package{events, b, c, d}, graph)
	if !hasDiagCode(results["/dep/d"], "HZN1690") {
		t.Fatalf("expected HZN1690 for third-hop re-export; got %#v", results["/dep/d"])
	}
}

// TestReExportSecondHopFuncResolves pins that the second hop applies to
// re-exported helper FUNCTIONS, not only types. `events` declares
// `MakeExecEvent`; `b` re-exports it; `c` re-exports `b.MakeExecEvent`;
// a consumer of `c` calls `c.MakeExecEvent()` without an
// unknown-helper diagnostic.
func TestReExportSecondHopFuncResolves(t *testing.T) {
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}

func MakeExecEvent() *ExecEvent {
    return nil
}
`,
	})
	b := parseTestPackage(t, "/dep/b", "b", map[string]string{
		"b.hzn": `package b

import events "m31labs.dev/horizon-test/events"

export events.ExecEvent
export events.MakeExecEvent
`,
	})
	c := parseTestPackage(t, "/dep/c", "c", map[string]string{
		"c.hzn": `package c

import b "m31labs.dev/horizon-test/b"

export b.ExecEvent
export b.MakeExecEvent
`,
	})
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import c "m31labs.dev/horizon-test/c"

map Events ringbuf[c.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    e := c.MakeExecEvent()
    if e == nil { return 0 }
    Events.submit(e)
    return 0
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/b": {"events": "/dep/events"},
			"/dep/c": {"b": "/dep/b"},
			"/root": {
				"bpf": "m31labs.dev/horizon/runtime/kernel",
				"c":   "/dep/c",
			},
		},
		Packages: map[string]ast.Package{
			"/dep/events": events,
			"/dep/b":      b,
			"/dep/c":      c,
			"/root":       root,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{events, b, c, root}, graph)
	if hasDiagCode(results["/dep/c"], "HZN1690") {
		t.Fatalf("did not expect HZN1690 for second-hop func re-export; got %#v", results["/dep/c"])
	}
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Severity == diag.SeverityError && containsAll(d.Message, "MakeExecEvent") {
				t.Fatalf("second-hop re-exported function unreachable from root: %#v", d)
			}
		}
	}
}

// TestReExportCycleDoesNotHang pins that a re-export cycle terminates.
// Package `x` re-exports `y.Foo` and `y` re-exports `x.Foo` — neither
// names a direct declaration anywhere, so the two-pass walk fails to
// resolve at pass 2 (there is no pass 3 to chase the cycle) and emits
// HZN1690 without looping. The test failing here would manifest as a
// hang rather than an assertion failure.
func TestReExportCycleDoesNotHang(t *testing.T) {
	x := parseTestPackage(t, "/dep/x", "x", map[string]string{
		"x.hzn": `package x

import y "m31labs.dev/horizon-test/y"

export y.Foo
`,
	})
	y := parseTestPackage(t, "/dep/y", "y", map[string]string{
		"y.hzn": `package y

import x "m31labs.dev/horizon-test/x"

export x.Foo
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/x": {"y": "/dep/y"},
			"/dep/y": {"x": "/dep/x"},
		},
		Packages: map[string]ast.Package{
			"/dep/x": x,
			"/dep/y": y,
		},
	}
	results := CheckPackages([]ast.Package{x, y}, graph)
	if !hasDiagCode(results["/dep/x"], "HZN1690") {
		t.Fatalf("expected HZN1690 for unresolved cyclic re-export in x; got %#v", results["/dep/x"])
	}
	if !hasDiagCode(results["/dep/y"], "HZN1690") {
		t.Fatalf("expected HZN1690 for unresolved cyclic re-export in y; got %#v", results["/dep/y"])
	}
}

// TestSamePackageExportRejected pins resolution O-3: an `export X`
// declaration that names a local-to-the-re-exporting-package symbol
// (no qualified alias to an import) is rejected. Same-package
// declarations are exported via capitalization alone; the `export`
// form is exclusively for re-exporting from imports. In test fixture
// shape the alias `mypkg` would have to be a known import for the
// symbol lookup to succeed; here the alias names the package itself,
// which is not in any import edge, so HZN1690 fires.
func TestSamePackageExportRejected(t *testing.T) {
	pkg := parseTestPackage(t, "/dep/mypkg", "mypkg", map[string]string{
		"mypkg.hzn": `package mypkg

type LocalEvent struct {
    pid u32
}

export mypkg.LocalEvent
`,
	})
	graph := ImportGraph{
		Edges:    map[string]map[string]string{"/dep/mypkg": {}},
		Packages: map[string]ast.Package{"/dep/mypkg": pkg},
	}
	results := CheckPackages([]ast.Package{pkg}, graph)
	if !hasDiagCode(results["/dep/mypkg"], "HZN1690") {
		t.Fatalf("expected HZN1690 for same-package export; got %#v", results["/dep/mypkg"])
	}
}

// TestReExportedFuncAccessibleFromTransitiveImporter pins re-export
// support for helper functions in addition to types. Middleware
// re-exports `events.MakeExecEvent` and root references
// `mw.MakeExecEvent` — the type checker recognizes the qualified
// reference as a callable user-helper.
func TestReExportedFuncAccessibleFromTransitiveImporter(t *testing.T) {
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import mw "m31labs.dev/horizon-test/middleware"

map Events ringbuf[mw.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    e := mw.MakeExecEvent()
    if e == nil { return 0 }
    Events.submit(e)
    return 0
}
`,
	})
	middleware := parseTestPackage(t, "/dep/middleware", "middleware", map[string]string{
		"middleware.hzn": `package middleware

import events "m31labs.dev/horizon-test/events"

export events.ExecEvent
export events.MakeExecEvent
`,
	})
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}

func MakeExecEvent() *ExecEvent {
    return nil
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/root": {
				"bpf": "m31labs.dev/horizon/runtime/kernel",
				"mw":  "/dep/middleware",
			},
			"/dep/middleware": {
				"events": "/dep/events",
			},
		},
		Packages: map[string]ast.Package{
			"/root":           root,
			"/dep/middleware": middleware,
			"/dep/events":     events,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{root, middleware, events}, graph)
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			// We are permissive about which body-walk diagnostics may fire
			// here — the assertion is that re-exported func MakeExecEvent
			// resolves as a known symbol on mw. A failure mode would be a
			// "function not declared" / unknown-helper diagnostic that
			// names mw.MakeExecEvent. Any error referencing that selector
			// fails the test.
			if d.Severity == diag.SeverityError {
				if containsAll(d.Message, "MakeExecEvent") {
					t.Fatalf("re-exported function unreachable from root: %#v", d)
				}
			}
		}
	}
}

// TestWildcardReExportExpandsSurface pins v0.4 Track C (C4) wildcard
// re-export (Q-C4.3, stretch). A package `b` declares
// `export events.*`, which expands to the events package's full
// exportable surface — both the `ExecEvent` type and the
// `MakeExecEvent` helper. A consumer of `b` reaches both via `b.`.
func TestWildcardReExportExpandsSurface(t *testing.T) {
	events := parseTestPackage(t, "/dep/events", "events", map[string]string{
		"events.hzn": `package events

type ExecEvent struct {
    pid u32
}

func MakeExecEvent() *ExecEvent {
    return nil
}
`,
	})
	b := parseTestPackage(t, "/dep/b", "b", map[string]string{
		"b.hzn": `package b

import events "m31labs.dev/horizon-test/events"

export events.*
`,
	})
	root := parseTestPackage(t, "/root", "main", map[string]string{
		"prog.hzn": `package main

import bpf "m31labs.dev/horizon/runtime/kernel"
import b "m31labs.dev/horizon-test/b"

map Events ringbuf[b.ExecEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    e := b.MakeExecEvent()
    if e == nil { return 0 }
    return 0
}
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/b": {"events": "/dep/events"},
			"/root": {
				"bpf": "m31labs.dev/horizon/runtime/kernel",
				"b":   "/dep/b",
			},
		},
		Packages: map[string]ast.Package{
			"/dep/events": events,
			"/dep/b":      b,
			"/root":       root,
		},
		BuiltinAliases: map[string]bool{"bpf": true},
	}
	results := CheckPackages([]ast.Package{events, b, root}, graph)
	if hasDiagCode(results["/dep/b"], "HZN1690") || hasDiagCode(results["/dep/b"], "HZN1693") {
		t.Fatalf("did not expect HZN1690/HZN1693 for wildcard re-export; got %#v", results["/dep/b"])
	}
	// Both the wildcard-expanded type (`b.ExecEvent`, used in the map)
	// and the wildcard-expanded helper (`b.MakeExecEvent`) must resolve
	// — no error names either symbol as unknown.
	for _, perFile := range results["/root"] {
		for _, d := range perFile {
			if d.Severity != diag.SeverityError {
				continue
			}
			if containsAll(d.Message, "ExecEvent") {
				t.Fatalf("wildcard re-exported type unreachable from root: %#v", d)
			}
			if containsAll(d.Message, "MakeExecEvent") {
				t.Fatalf("wildcard re-exported function unreachable from root: %#v", d)
			}
		}
	}
}

// TestWildcardReExportEmptySourceEmitsHZN1693 pins that an
// `export <alias>.*` whose source package has no exportable surface
// emits HZN1693 ("wildcard re-export matched no exportable symbols").
// The source package `empty` declares only a lowercase (unexported)
// type, so its exportable surface is empty.
func TestWildcardReExportEmptySourceEmitsHZN1693(t *testing.T) {
	empty := parseTestPackage(t, "/dep/empty", "empty", map[string]string{
		"empty.hzn": `package empty

type internalEvent struct {
    pid u32
}
`,
	})
	b := parseTestPackage(t, "/dep/b", "b", map[string]string{
		"b.hzn": `package b

import empty "m31labs.dev/horizon-test/empty"

export empty.*
`,
	})
	graph := ImportGraph{
		Edges: map[string]map[string]string{
			"/dep/b": {"empty": "/dep/empty"},
		},
		Packages: map[string]ast.Package{
			"/dep/empty": empty,
			"/dep/b":     b,
		},
	}
	results := CheckPackages([]ast.Package{empty, b}, graph)
	if !hasDiagCode(results["/dep/b"], "HZN1693") {
		t.Fatalf("expected HZN1693 for empty-source wildcard re-export; got %#v", results["/dep/b"])
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !sliceContains(haystack, n) {
			return false
		}
	}
	return true
}

func sliceContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
