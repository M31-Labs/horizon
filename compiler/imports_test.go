package compiler

import (
	"errors"
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

// --- Remote-import resolver tests (roadmap #14) ---

// seedFixture pre-populates the content-addressed cache for `repo@ref`
// with one .hzn file declaring the requested package name. Returns the
// cache root path (for use as HORIZON_CACHE_ROOT) and the resulting
// content sha256.
func seedFixture(t *testing.T, repo, ref, pkgName, body string) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	dest := filepath.Join(root, cacheKey(repo), ref)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	contents := "package " + pkgName + "\n\n" + body
	if err := os.WriteFile(filepath.Join(dest, pkgName+".hzn"), []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile fixture: %v", err)
	}
	sum, err := hashDirSHA256(dest)
	if err != nil {
		t.Fatalf("hash fixture: %v", err)
	}
	return root, sum
}

func TestIsRemoteImportShapeAcceptsM31labs(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// github.com — unchanged from v0.3.
		{"github.com/org/repo", true},
		{"github.com/org", false},
		// m31labs.dev — newly accepted (C1, ≥3 segments).
		{"m31labs.dev/org/repo", true},
		{"m31labs.dev/m31labs/horizon-events", true},
		{"m31labs.dev/org", false},
		{"m31labs.dev", false},
		// Arbitrary hosts still fall through to the vendor walk.
		{"example.com/org/repo", false},
	}
	for _, c := range cases {
		if got := isRemoteImportShape(c.path); got != c.want {
			t.Errorf("isRemoteImportShape(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestResolveImportsM31labsMetaRedirectUpdateMode(t *testing.T) {
	// End-to-end: a m31labs.dev import in lockfile-update mode resolves
	// its clone URL via httpDiscover, resolves the tag via resolveRef,
	// fetches via gitClone, and produces a LockfileEntry. All three
	// injection points are stubbed; no network.
	repo := "m31labs.dev/m31labs/horizon-test-events"
	tag := "v1.0.0"
	resolvedRef := "abc1234567890abcdef1234567890abcdef12345"
	const discovered = "https://github.com/m31labs/horizon-test-events.git"

	cacheR := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", cacheR)

	discoverCalls := 0
	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		discoverCalls++
		if host != "m31labs.dev" {
			t.Errorf("httpDiscover host = %q, want m31labs.dev", host)
		}
		return discovered, nil
	})()

	prevResolve := resolveRef
	resolveRef = func(url, ver string) (string, error) {
		if url != discovered {
			t.Errorf("resolveRef url = %q, want discovered %q", url, discovered)
		}
		if ver == tag {
			return resolvedRef, nil
		}
		return "", nil
	}
	defer func() { resolveRef = prevResolve }()

	defer withGitCloneStub(t, func(gotURL, gotRef, gotDest string) error {
		if gotURL != discovered {
			t.Errorf("gitClone url = %q, want discovered %q", gotURL, discovered)
		}
		if err := os.MkdirAll(gotDest, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(gotDest, "events.hzn"), []byte("package events\n"), 0o644)
	})()

	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "`+repo+`@`+tag+`"

type Wrapper struct {
    x u32
}
`)
	res, err := ResolveImportsOpts(dir, ResolveOpts{
		Ctx:            DetectContext(),
		LockfileUpdate: true,
	})
	if err != nil {
		t.Fatalf("ResolveImportsOpts: %v", err)
	}
	if diag.HasErrors(res.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", res.Diagnostics)
	}
	if discoverCalls < 1 {
		t.Fatalf("httpDiscover called %d times, want >= 1", discoverCalls)
	}
	if len(res.LockfileUpdate) != 1 {
		t.Fatalf("LockfileUpdate = %d, want 1", len(res.LockfileUpdate))
	}
	entry := res.LockfileUpdate[0]
	if entry.Path != repo {
		t.Fatalf("entry.Path = %q, want %q", entry.Path, repo)
	}
	if entry.RefResolved != resolvedRef {
		t.Fatalf("entry.RefResolved = %q, want %q", entry.RefResolved, resolvedRef)
	}
}

func TestResolveImportsM31labsMetaRedirectDiscoveryFailureHZN1705(t *testing.T) {
	// A m31labs.dev import whose meta-redirect discovery fails surfaces
	// HZN1705 and resolves nothing.
	repo := "m31labs.dev/m31labs/horizon-test-events"
	tag := "v1.0.0"

	cacheR := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", cacheR)

	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		return "", errors.New("simulated discovery failure: 404 Not Found")
	})()

	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "`+repo+`@`+tag+`"

type Wrapper struct {
    x u32
}
`)
	res, err := ResolveImportsOpts(dir, ResolveOpts{
		Ctx:            DetectContext(),
		LockfileUpdate: true,
	})
	if err != nil {
		t.Fatalf("ResolveImportsOpts: %v", err)
	}
	found := false
	for _, d := range res.Diagnostics {
		if d.Code == "HZN1705" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HZN1705 (meta-redirect discovery failed), got %#v", res.Diagnostics)
	}
	if len(res.LockfileUpdate) != 0 {
		t.Fatalf("LockfileUpdate = %d, want 0 on discovery failure", len(res.LockfileUpdate))
	}
}

func TestResolveImportsResolvesGithubURLWithLockfile(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"
	_, sum := seedFixture(t, repo, ref, "events", `type Exec struct {
    pid u32
}
`)
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "github.com/m31labs/horizon-test-events@v1.0.0"

type Wrapper struct {
    pid u32
}
`)
	writeFile(t, dir, "hzn.lock", `{
  "schema": "m31labs.dev/horizon/lockfile/v1",
  "entries": [
    {
      "path": "`+repo+`",
      "version": "v1.0.0",
      "ref_resolved": "`+ref+`",
      "sha256": "`+sum+`"
    }
  ]
}
`)
	_, deps, graph, diags, err := ResolveImports(dir)
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
	rootAbs, _ := filepath.Abs(dir)
	if _, ok := graph.Edges[rootAbs]["events"]; !ok {
		t.Fatalf("graph.Edges missing events alias: %#v", graph.Edges)
	}
}

func TestResolveImportsLockfileMissingEntryHZN1701(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"
	seedFixture(t, repo, ref, "events", "")
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "github.com/m31labs/horizon-test-events@v1.0.0"

type Wrapper struct {
    x u32
}
`)
	// No hzn.lock at all — entry missing.
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1701" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1701 (lockfile entry missing), got %#v", diags)
	}
}

func TestResolveImportsLockfileChecksumMismatchHZN1700(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"
	seedFixture(t, repo, ref, "events", `type Exec struct {
    pid u32
}
`)
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "github.com/m31labs/horizon-test-events@v1.0.0"

type Wrapper struct {
    pid u32
}
`)
	bogusSum := strings.Repeat("0", 64)
	writeFile(t, dir, "hzn.lock", `{
  "schema": "m31labs.dev/horizon/lockfile/v1",
  "entries": [
    {
      "path": "`+repo+`",
      "version": "v1.0.0",
      "ref_resolved": "`+ref+`",
      "sha256": "`+bogusSum+`"
    }
  ]
}
`)
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1700" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1700 (checksum mismatch), got %#v", diags)
	}
}

func TestResolveImportsInvalidVersionSyntaxHZN1704(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "github.com/m31labs/horizon-test-events@latest"

type Wrapper struct {
    x u32
}
`)
	_, _, _, diags, err := ResolveImports(dir)
	if err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1704" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1704 (invalid version syntax), got %#v", diags)
	}
}

func TestResolveImportsLockfileUpdateAppendsEntry(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	// Tag we'd resolve to a SHA in production; we'll stub gitClone +
	// resolveRef to make this deterministic.
	tag := "v1.0.0"
	resolvedRef := "abc1234567890abcdef1234567890abcdef12345"

	// Pre-seed the cache as if the fetch had already run.
	cacheR := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", cacheR)
	dest := filepath.Join(cacheR, cacheKey(repo), resolvedRef)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "events.hzn"), []byte("package events\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Stub resolveRef so lockfile-update mode doesn't try ls-remote.
	prevResolve := resolveRef
	resolveRef = func(repoURL, ver string) (string, error) {
		if ver == tag {
			return resolvedRef, nil
		}
		return "", nil
	}
	defer func() { resolveRef = prevResolve }()

	dir := t.TempDir()
	writeFile(t, dir, "main.hzn", `package main

import events "`+repo+`@`+tag+`"

type Wrapper struct {
    x u32
}
`)
	res, err := ResolveImportsOpts(dir, ResolveOpts{
		Ctx:            DetectContext(),
		LockfileUpdate: true,
	})
	if err != nil {
		t.Fatalf("ResolveImportsOpts: %v", err)
	}
	if diag.HasErrors(res.Diagnostics) {
		t.Fatalf("diagnostics = %#v", res.Diagnostics)
	}
	if len(res.LockfileUpdate) != 1 {
		t.Fatalf("LockfileUpdate = %d, want 1", len(res.LockfileUpdate))
	}
	entry := res.LockfileUpdate[0]
	if entry.Path != repo {
		t.Fatalf("entry.Path = %q, want %q", entry.Path, repo)
	}
	if entry.Version != tag {
		t.Fatalf("entry.Version = %q", entry.Version)
	}
	if entry.RefResolved != resolvedRef {
		t.Fatalf("entry.RefResolved = %q", entry.RefResolved)
	}
	if len(entry.SHA256) != 64 {
		t.Fatalf("entry.SHA256 should be 64-char hex, got %q", entry.SHA256)
	}
}

