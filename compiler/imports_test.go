package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func writeFile(t *testing.T, dir, name, contents string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", full, err)
	}
}

func TestResolveImportsSinglePackageNoImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

type Foo struct {
    a u32
}
`)
	root, deps, graph, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if root.Name != "main" {
		t.Fatalf("root.Name = %q, want main", root.Name)
	}
	if len(root.Files) != 1 {
		t.Fatalf("root.Files = %d, want 1", len(root.Files))
	}
	if len(deps) != 0 {
		t.Fatalf("deps = %d, want 0", len(deps))
	}
	if len(graph.Edges) != 0 {
		t.Fatalf("graph.Edges = %#v, want empty", graph.Edges)
	}
}

func TestResolveImportsHardcodedBPFImport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import bpf "m31labs.dev/horizon/runtime/kernel"

@capability("kernel.process.exec.observe")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	root, deps, graph, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if len(deps) != 0 {
		t.Fatalf("deps = %d, want 0 (builtins shouldn't produce a dep package)", len(deps))
	}
	if !graph.BuiltinAliases["bpf"] {
		t.Fatalf("BuiltinAliases = %#v, want bpf entry", graph.BuiltinAliases)
	}
	// Edges record the alias -> resolved path for every importer; for the
	// root that's keyed by the absolute directory we resolved against.
	var found bool
	for _, edges := range graph.Edges {
		if resolved, ok := edges["bpf"]; ok {
			found = true
			if resolved != "m31labs.dev/horizon/runtime/kernel" {
				t.Fatalf("resolved path for bpf = %q, want canonical builtin path", resolved)
			}
			break
		}
	}
	if !found {
		t.Fatalf("alias bpf not found in any edge map: %v", graph.Edges)
	}
	// Root package's ImportEdges should also carry the resolved alias with
	// Builtin=true.
	if len(root.ImportEdges) != 1 {
		t.Fatalf("root.ImportEdges = %d, want 1", len(root.ImportEdges))
	}
	if !root.ImportEdges[0].Builtin {
		t.Fatalf("root.ImportEdges[0].Builtin = false, want true")
	}
}

func TestResolveImportsBuiltinAnyAlias(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import bee "m31labs.dev/horizon/runtime/kernel"

@capability("kernel.process.exec.observe")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	_, _, graph, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if !graph.BuiltinAliases["bee"] {
		t.Fatalf("BuiltinAliases = %#v, want bee entry (any alias may bind to a builtin path)", graph.BuiltinAliases)
	}
}

func TestResolveImportsRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "./events"

type Wrapper struct {
    a u32
}
`)
	writeFile(t, dir, "events/events.hzn", `package events

type ExecEvent struct {
    ts_ns u64
}
`)
	root, deps, graph, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %d, want 1", len(deps))
	}
	if deps[0].Name != "events" {
		t.Fatalf("deps[0].Name = %q, want events", deps[0].Name)
	}
	if len(deps[0].Files) != 1 {
		t.Fatalf("deps[0].Files = %d, want 1", len(deps[0].Files))
	}
	// Edge should resolve events alias to the events package path.
	var foundEdges map[string]string
	for _, e := range graph.Edges {
		if _, ok := e["events"]; ok {
			foundEdges = e
			break
		}
	}
	if foundEdges == nil {
		t.Fatalf("no edges contained alias 'events'; graph = %#v", graph.Edges)
	}
	if !strings.Contains(foundEdges["events"], "events") {
		t.Fatalf("resolved events path = %q, expected to contain 'events'", foundEdges["events"])
	}
	_ = root
}

func TestResolveImportsVendoredPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "m31labs.dev/myorg/events"

type Wrapper struct {
    a u32
}
`)
	writeFile(t, dir, "vendor/m31labs.dev/myorg/events/events.hzn", `package events

type ExecEvent struct {
    ts_ns u64
}
`)
	_, deps, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %d, want 1", len(deps))
	}
	if deps[0].Name != "events" {
		t.Fatalf("deps[0].Name = %q, want events", deps[0].Name)
	}
}

func TestResolveImportsAbsolutePathWarns(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "shared")
	writeFile(t, pkgDir, "events.hzn", `package events

type ExecEvent struct {
    ts_ns u64
}
`)
	writeFile(t, dir, "main.hzn", `package main

import events "`+pkgDir+`"

type Wrapper struct {
    a u32
}
`)
	_, deps, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want no errors (absolute path is a warning)", diags)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %d, want 1", len(deps))
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1556" && d.Severity == diag.SeverityWarning {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1556 warning, got diagnostics: %#v", diags)
	}
}

func TestResolveImportsErrorImportNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import missing "m31labs.dev/nowhere/missing"

type Wrapper struct {
    a u32
}
`)
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1554" && d.Severity == diag.SeverityError {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1554 error, got diagnostics: %#v", diags)
	}
}

// TestResolveImportsFiltersByBuildTag pins O-4: two files in the same
// package directory with mutually exclusive `//hzn:build` constraints
// is legal. Under HORIZON_BUILD_OS=linux only the linux-tagged file
// contributes to the package; the darwin-tagged file is filtered out
// before parsing and produces no diagnostics.
func TestResolveImportsFiltersByBuildTag(t *testing.T) {
	t.Setenv("HORIZON_BUILD_OS", "linux")
	t.Setenv("HORIZON_BUILD_ARCH", "amd64")
	t.Setenv("HORIZON_BUILD_KERNEL", "5.15")
	t.Setenv("HORIZON_BUILD_BTF", "0")
	resetContextCache()
	t.Cleanup(resetContextCache)

	dir := t.TempDir()
	writeFile(t, dir, "linux.hzn", `//hzn:build linux

package mfbt

type LinuxOnly struct {
    x u32
}
`)
	writeFile(t, dir, "darwin.hzn", `//hzn:build darwin

package mfbt

type DarwinOnly struct {
    x u32
}
`)
	root, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if len(root.Files) != 1 {
		t.Fatalf("root.Files = %d, want 1 (darwin file should be filtered out)", len(root.Files))
	}
	// The surviving file should be linux.hzn — assert by checking its
	// recorded BuildTag.
	if root.Files[0].BuildTag != "linux" {
		t.Fatalf("surviving file BuildTag = %q, want %q", root.Files[0].BuildTag, "linux")
	}
}

// TestResolveImportsEmitsHZN1680WhenAllFilesExcluded covers the diagnostic
// that fires when an *imported* package directory has every file filtered
// out by the active build context.
func TestResolveImportsEmitsHZN1680WhenAllFilesExcluded(t *testing.T) {
	t.Setenv("HORIZON_BUILD_OS", "linux")
	t.Setenv("HORIZON_BUILD_ARCH", "amd64")
	t.Setenv("HORIZON_BUILD_KERNEL", "5.15")
	t.Setenv("HORIZON_BUILD_BTF", "0")
	resetContextCache()
	t.Cleanup(resetContextCache)

	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import other "./other"

type Wrapper struct {
    a u32
}
`)
	writeFile(t, dir, "other/other.hzn", `//hzn:build darwin

package other

type Foo struct {
    x u32
}
`)
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	var found bool
	for _, d := range diags {
		if d.Code == "HZN1680" && d.Severity == diag.SeverityError {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1680 error, got diagnostics: %#v", diags)
	}
}

// TestResolveImportsBuildTagSurvivesPartialExclusion pins that when at
// least one file in a package survives the filter, HZN1680 does NOT fire
// (only-all-files-excluded triggers it).
func TestResolveImportsBuildTagSurvivesPartialExclusion(t *testing.T) {
	t.Setenv("HORIZON_BUILD_OS", "linux")
	t.Setenv("HORIZON_BUILD_ARCH", "amd64")
	t.Setenv("HORIZON_BUILD_KERNEL", "5.15")
	t.Setenv("HORIZON_BUILD_BTF", "0")
	resetContextCache()
	t.Cleanup(resetContextCache)

	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import other "./other"

type Wrapper struct {
    a u32
}
`)
	writeFile(t, dir, "other/linux.hzn", `//hzn:build linux

package other

type Foo struct {
    x u32
}
`)
	writeFile(t, dir, "other/darwin.hzn", `//hzn:build darwin

package other

type Bar struct {
    x u32
}
`)
	_, deps, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	for _, d := range diags {
		if d.Code == "HZN1680" {
			t.Fatalf("HZN1680 should not fire when at least one file survives the filter: %#v", d)
		}
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %d, want 1", len(deps))
	}
	if len(deps[0].Files) != 1 {
		t.Fatalf("deps[0].Files = %d, want 1 (only linux.hzn should survive)", len(deps[0].Files))
	}
}

func TestResolveImportsErrorImportCycle(t *testing.T) {
	dir := t.TempDir()
	// root imports A, A imports B, B imports A -> cycle.
	writeFile(t, dir, "main.hzn", `package main

import a "./a"

type Wrapper struct {
    a u32
}
`)
	writeFile(t, dir, "a/a.hzn", `package a

import b "../b"

type AT struct {
    x u32
}
`)
	writeFile(t, dir, "b/b.hzn", `package b

import a "../a"

type BT struct {
    x u32
}
`)
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1555" && d.Severity == diag.SeverityError {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1555 cycle error, got diagnostics: %#v", diags)
	}
}

