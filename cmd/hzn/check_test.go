package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
)

// jsonCheckEnvelopeForTest mirrors the production envelope shape so tests
// can decode `hzn check -json` output without depending on the
// (unexported) production type.
//
// v0.3 NOTE: in v0.2 the `hzn check -json` output was a bare JSON array
// of diag.Diagnostic; v0.3 wraps it in this object so the per-package
// manifest path (#12 / ADR-0006) can be discovered through the same
// stream. The migration guide flags the change as [BREAKING].
type jsonCheckEnvelopeForTest struct {
	Diagnostics []diag.Diagnostic `json:"diagnostics"`
	ManifestPath string           `json:"manifest_path,omitempty"`
}

func TestCheckJSONIncludesSourceContext(t *testing.T) {
	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", "../../testdata/invalid/packet_unproven_read.hzn", "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want diagnostics error")
	}
	var env jsonCheckEnvelopeForTest
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v\n%s", err, stdout)
	}
	diagnostics := env.Diagnostics
	if len(diagnostics) == 0 {
		t.Fatal("diagnostics = 0, want source-aware diagnostic")
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "ip.protocol") {
		t.Fatalf("source context = %#v, want authored packet line", diagnostics[0].Source)
	}
	if diagnostics[0].Source.Marker == "" {
		t.Fatalf("source marker is empty for %#v", diagnostics[0].Source)
	}
}

func TestCheckRejectsProgramWithoutCapabilityCoverage(t *testing.T) {
	input := filepath.Join(t.TempDir(), "nocap.hzn")
	if err := os.WriteFile(input, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", input, "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want missing capability diagnostic")
	}
	var env jsonCheckEnvelopeForTest
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v\n%s", err, stdout)
	}
	diagnostics := env.Diagnostics
	if len(diagnostics) != 1 || diagnostics[0].Code != "HZN3301" {
		t.Fatalf("diagnostics = %#v, want HZN3301", diagnostics)
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, `@tracepoint("sched:sched_process_exec")`) {
		t.Fatalf("source context = %#v, want section attribute line", diagnostics[0].Source)
	}
}

func TestCheckCapabilityNamespaceMismatchPointsAtCapability(t *testing.T) {
	input := filepath.Join(t.TempDir(), "wrongcap.hzn")
	if err := os.WriteFile(input, []byte(`package probes

@capability("kernel.process.exec.observe")
@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Pass
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", input, "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want capability namespace diagnostic")
	}
	var env jsonCheckEnvelopeForTest
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v\n%s", err, stdout)
	}
	diagnostics := env.Diagnostics
	if len(diagnostics) != 1 || diagnostics[0].Code != "HZN2502" {
		t.Fatalf("diagnostics = %#v, want HZN2502", diagnostics)
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, `@capability("kernel.process.exec.observe")`) {
		t.Fatalf("source context = %#v, want capability attribute line", diagnostics[0].Source)
	}
}

// TestCheckPinsCrossPackageFailureModes verifies that the four conflict-case
// fixtures landed in Phase 2 Subtask 6c each surface their expected
// diagnostic code when fed through `hzn check`. The fixtures live under
// testdata/invalid/import-*/ and testdata/invalid/capability-value-conflict/
// (plus testdata/invalid/import-not-found.hzn for the single-file case).
//
//   - import-not-found.hzn → HZN1554 (unresolved import path)
//   - import-cycle/         → HZN1555 (import cycle detected by the
//     resolver's DFS visited-set)
//   - import-alias-conflict/ → HZN1004 (extended) when an import alias
//     shadows a hardcoded compiler namespace such as `bpf`, `xdp`, etc.
//   - capability-value-conflict/ → HZN1553 (the aggregator-level advisory
//     when two packages contribute capabilities with the same value
//     string under different qualified names). HZN1560 is reserved for
//     same-qualified-name cross-package conflicts; that path is currently
//     defensive because upstream type-check (HZN1002) and validate
//     (HZN2503) catch the natural triggers first. This fixture pins the
//     aggregator code that is actually reachable through AnalyzePath
//     today.
func TestCheckPinsCrossPackageFailureModes(t *testing.T) {
	cases := []struct {
		path string
		code string
	}{
		{"../../testdata/invalid/import-not-found.hzn", "HZN1554"},
		{"../../testdata/invalid/import-cycle", "HZN1555"},
		{"../../testdata/invalid/import-alias-conflict", "HZN1004"},
		{"../../testdata/invalid/capability-value-conflict", "HZN1553"},
	}
	for _, tc := range cases {
		t.Run(tc.code+"/"+filepath.Base(tc.path), func(t *testing.T) {
			stdout, _ := captureStdout(t, func() error {
				return run([]string{"check", tc.path, "-json"})
			})
			var env jsonCheckEnvelopeForTest
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("unmarshal envelope: %v\n%s", err, stdout)
			}
			diagnostics := env.Diagnostics
			if !slices.ContainsFunc(diagnostics, func(d diag.Diagnostic) bool {
				return d.Code == tc.code
			}) {
				t.Fatalf("check %s diagnostics = %#v, want code %s", tc.path, diagnostics, tc.code)
			}
		})
	}
}

// writeCapabilityPackage writes a small but valid Horizon package with a
// single tracepoint capability into dir. Returned as a convenience for the
// per-package manifest tests in this file. (#12 / ADR-0006.)
func writeCapabilityPackage(t *testing.T, dir string) {
	t.Helper()
	source := []byte(`package probes

capability ExecObserve danger observe = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	other := []byte(`package probes

const KeepAlive u32 = 1
`)
	// Two files so the "alphabetically-first" file convention has
	// something to disambiguate.
	if err := os.WriteFile(filepath.Join(dir, "exec.hzn"), source, 0o600); err != nil {
		t.Fatalf("write exec.hzn: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "zz_aux.hzn"), other, 0o600); err != nil {
		t.Fatalf("write zz_aux.hzn: %v", err)
	}
}

// TestCheckEmitsPerPackageManifest asserts that `hzn check <dir>` writes
// `<dir>/<pkg>.pkg.cap.json` adjacent to the alphabetically-first source
// file when the package declares ≥1 capability. (#12 / ADR-0006.)
func TestCheckEmitsPerPackageManifest(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", dir})
	}); err != nil {
		t.Fatalf("hzn check %s: %v", dir, err)
	}

	want := filepath.Join(dir, "probes.pkg.cap.json")
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read manifest at %s: %v", want, err)
	}
	var m capability.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest at %s: %v\n%s", want, err, data)
	}
	if len(m.Capabilities) == 0 {
		t.Fatalf("manifest %s carries zero capabilities, want ≥1: %#v", want, m)
	}
}

// TestCheckOmitsManifestWhenNoCapabilities asserts that pure type/helper
// packages (no capability declarations) get no `.pkg.cap.json`. The
// artifact is a *capability* manifest; emitting an empty one is noise.
// (#12 / ADR-0006.)
func TestCheckOmitsManifestWhenNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := []byte(`package events

type ExecEvent struct {
    ts_ns u64
    pid u32
}
`)
	if err := os.WriteFile(filepath.Join(dir, "events.hzn"), src, 0o600); err != nil {
		t.Fatalf("write events.hzn: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", dir})
	}); err != nil {
		t.Fatalf("hzn check %s: %v", dir, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pkg.cap.json") {
			t.Fatalf("unexpected per-package manifest emitted: %s", e.Name())
		}
	}
}

// TestCheckHonorsManifestOutFlag asserts that `-manifest-out <path>`
// relocates the side-artifact. The default emission location is
// suppressed when the override is set. (#12 / ADR-0006.)
func TestCheckHonorsManifestOutFlag(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	outDir := t.TempDir()
	out := filepath.Join(outDir, "custom.cap.json")

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", dir, "-manifest-out", out})
	}); err != nil {
		t.Fatalf("hzn check -manifest-out: %v", err)
	}

	if _, err := os.Stat(out); err != nil {
		t.Fatalf("override manifest not at %s: %v", out, err)
	}
	defaultPath := filepath.Join(dir, "probes.pkg.cap.json")
	if _, err := os.Stat(defaultPath); !os.IsNotExist(err) {
		t.Fatalf("default manifest written despite -manifest-out: stat err = %v", err)
	}
}

// TestCheckHonorsNoManifestFlag asserts that `-no-manifest` suppresses
// the side-artifact entirely. Intended for IDE-driven callers that want
// a pure read-only check. (#12 / ADR-0006.)
func TestCheckHonorsNoManifestFlag(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", dir, "-no-manifest"})
	}); err != nil {
		t.Fatalf("hzn check -no-manifest: %v", err)
	}

	defaultPath := filepath.Join(dir, "probes.pkg.cap.json")
	if _, err := os.Stat(defaultPath); !os.IsNotExist(err) {
		t.Fatalf("default manifest written despite -no-manifest: stat err = %v", err)
	}
}

// TestCheckPrintsManifestPathToStdout asserts that text-mode `hzn check`
// announces the manifest path on stdout after the "check passed" line so
// users can discover the artifact without filesystem walking. (#12 /
// ADR-0006.)
func TestCheckPrintsManifestPathToStdout(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", dir})
	})
	if err != nil {
		t.Fatalf("hzn check %s: %v", dir, err)
	}
	if !strings.Contains(stdout, "wrote per-package manifest:") {
		t.Fatalf("stdout missing manifest discovery line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "probes.pkg.cap.json") {
		t.Fatalf("stdout missing manifest filename:\n%s", stdout)
	}
}

// TestCheckJSONEnvelopeIncludesManifestPath asserts that `hzn check -json`
// returns the new v0.3 envelope shape (object with `diagnostics` and
// `manifest_path` fields) with `manifest_path` populated when a
// per-package manifest was emitted. The v0.2 bare-array shape is
// retired; the migration guide flags this as [BREAKING]. (#12 /
// ADR-0006.)
func TestCheckJSONEnvelopeIncludesManifestPath(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", dir, "-json"})
	})
	if err != nil {
		t.Fatalf("hzn check %s -json: %v", dir, err)
	}
	var env jsonCheckEnvelopeForTest
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v\n%s", err, stdout)
	}
	if env.ManifestPath == "" {
		t.Fatalf("envelope.ManifestPath empty, want per-package manifest path: %s", stdout)
	}
	if !strings.HasSuffix(env.ManifestPath, "probes.pkg.cap.json") {
		t.Fatalf("envelope.ManifestPath = %q, want suffix probes.pkg.cap.json", env.ManifestPath)
	}
}

// TestCheckJSONEnvelopeOmitsManifestPathWhenSuppressed asserts that the
// new envelope's `manifest_path` field is omitempty — when emission is
// suppressed (or no capabilities), JSON output carries no `manifest_path`
// key. (#12 / ADR-0006.)
func TestCheckJSONEnvelopeOmitsManifestPathWhenSuppressed(t *testing.T) {
	dir := t.TempDir()
	writeCapabilityPackage(t, dir)

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", dir, "-json", "-no-manifest"})
	})
	if err != nil {
		t.Fatalf("hzn check %s -json -no-manifest: %v", dir, err)
	}
	if strings.Contains(stdout, "manifest_path") {
		t.Fatalf("envelope contains manifest_path despite -no-manifest:\n%s", stdout)
	}
}

// checkCacheKey mirrors compiler.cacheKey (unexported) so the C3
// lockfile-update tests can seed the fixture cache under the directory
// name the resolver will look for. Same algorithm as hznGetCacheKey in
// get_test.go (kept local to keep each test file self-contained).
func checkCacheKey(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return hex.EncodeToString(sum[:])[:32]
}

// seedRemoteImportFixture pre-seeds a content-addressed cache entry for
// repo@ref and writes a build root that imports it by SHA-as-version.
// Pinning by a ≥7-char hex SHA makes the resolver short-circuit
// resolveRef (no ls-remote / network), so the lockfile-update path runs
// deterministically in CI. Returns the build root directory.
func seedRemoteImportFixture(t *testing.T, repo, ref string) string {
	t.Helper()

	cacheRoot := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", cacheRoot)
	dest := filepath.Join(cacheRoot, checkCacheKey(repo), ref)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("MkdirAll cache fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "events.hzn"),
		[]byte("package events\n\ntype Exec struct {\n    pid u32\n}\n"), 0o644); err != nil {
		t.Fatalf("write cache fixture: %v", err)
	}

	buildRoot := t.TempDir()
	src := []byte("package probes\n\nimport events \"" + repo + "@" + ref + "\"\n")
	if err := os.WriteFile(filepath.Join(buildRoot, "probes.hzn"), src, 0o644); err != nil {
		t.Fatalf("write build root source: %v", err)
	}
	return buildRoot
}

// lockEntry is the minimal decode shape shared by the C3 tests.
type lockEntry struct {
	Path        string `json:"path"`
	Version     string `json:"version"`
	RefResolved string `json:"ref_resolved"`
	SHA256      string `json:"sha256"`
}

func readLockEntries(t *testing.T, buildRoot string) []lockEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(buildRoot, "hzn.lock"))
	if err != nil {
		t.Fatalf("read hzn.lock: %v", err)
	}
	var lf struct {
		Schema  string      `json:"schema"`
		Entries []lockEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &lf); err != nil {
		t.Fatalf("unmarshal hzn.lock: %v", err)
	}
	return lf.Entries
}

// TestCheckLockfileUpdateWritesLockfile asserts `hzn check -lockfile-update`
// batch-resolves an unpinned remote import and writes the resulting entry
// into hzn.lock. This is the batch analog of `hzn get` (C3 / ADR-0009 O-1).
func TestCheckLockfileUpdateWritesLockfile(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"
	buildRoot := seedRemoteImportFixture(t, repo, ref)

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", buildRoot, "-lockfile-update"})
	}); err != nil {
		t.Fatalf("hzn check -lockfile-update: %v", err)
	}

	entries := readLockEntries(t, buildRoot)
	if len(entries) != 1 {
		t.Fatalf("hzn.lock entries = %d, want 1: %#v", len(entries), entries)
	}
	e := entries[0]
	if e.Path != repo {
		t.Fatalf("entry.Path = %q, want %q", e.Path, repo)
	}
	if e.Version != ref {
		t.Fatalf("entry.Version = %q, want %q (SHA-as-version)", e.Version, ref)
	}
	if e.RefResolved != ref {
		t.Fatalf("entry.RefResolved = %q, want %q", e.RefResolved, ref)
	}
	if len(e.SHA256) != 64 {
		t.Fatalf("entry.SHA256 = %q, want 64-char hex", e.SHA256)
	}
}

// TestCheckVerifyModeLeavesLockfileUntouched asserts that the default
// (flag-absent) `hzn check` never mutates hzn.lock — it stays verify-only.
// We pre-write a lockfile that already pins the import, run a plain check,
// and confirm the file is byte-for-byte identical afterward.
func TestCheckVerifyModeLeavesLockfileUntouched(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"
	buildRoot := seedRemoteImportFixture(t, repo, ref)

	// First, produce a valid lockfile via the update path.
	if _, err := captureStdout(t, func() error {
		return run([]string{"check", buildRoot, "-lockfile-update"})
	}); err != nil {
		t.Fatalf("seed lockfile via -lockfile-update: %v", err)
	}
	lockPath := filepath.Join(buildRoot, "hzn.lock")
	before, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read seeded hzn.lock: %v", err)
	}

	// Now a plain verify-mode check must not rewrite the lockfile.
	if _, err := captureStdout(t, func() error {
		return run([]string{"check", buildRoot})
	}); err != nil {
		t.Fatalf("verify-mode hzn check: %v", err)
	}
	after, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read hzn.lock after verify: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("verify-mode check mutated hzn.lock:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestCheckLockfileUpdateNoRemoteImportsNoOp asserts that
// `-lockfile-update` on a package with no remote imports is a clean no-op:
// the check passes and no hzn.lock is created.
func TestCheckLockfileUpdateNoRemoteImportsNoOp(t *testing.T) {
	dir := t.TempDir()
	src := []byte(`package probes

capability ExecObserve danger observe = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	if err := os.WriteFile(filepath.Join(dir, "probes.hzn"), src, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return run([]string{"check", dir, "-lockfile-update"})
	}); err != nil {
		t.Fatalf("hzn check -lockfile-update (no remote imports): %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "hzn.lock")); !os.IsNotExist(err) {
		t.Fatalf("hzn.lock created for package with no remote imports: stat err = %v", err)
	}
}
