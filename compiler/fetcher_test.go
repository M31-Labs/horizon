package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/horizon/compiler/diag"
)

// withGitCloneStub swaps the package-level gitClone variable for the
// duration of a single test. Returns a restore func to defer.
func withGitCloneStub(t *testing.T, stub func(repo, ref, dest string) error) func() {
	t.Helper()
	prev := gitClone
	gitClone = stub
	return func() { gitClone = prev }
}

// setCacheRoot points HORIZON_CACHE_ROOT at a fresh tempdir for a single
// test and clears the related XDG env vars so the fetcher's cacheRoot()
// resolves to the override.
func setCacheRoot(t *testing.T, root string) func() {
	t.Helper()
	prev, hadPrev := os.LookupEnv("HORIZON_CACHE_ROOT")
	t.Setenv("HORIZON_CACHE_ROOT", root)
	return func() {
		if hadPrev {
			os.Setenv("HORIZON_CACHE_ROOT", prev)
		} else {
			os.Unsetenv("HORIZON_CACHE_ROOT")
		}
	}
}

func TestFetchCacheHitSkipsClone(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234"
	key := cacheKey(repo)
	dest := filepath.Join(root, key, ref)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Sentinel file proves we return the pre-populated dir without re-cloning.
	if err := os.WriteFile(filepath.Join(dest, "events.hzn"), []byte("package events\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	defer withGitCloneStub(t, func(_, _, _ string) error {
		t.Fatalf("gitClone called despite cache hit")
		return nil
	})()
	got, diags, err := Fetch(repo, ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if got != dest {
		t.Fatalf("Fetch returned %q, want %q", got, dest)
	}
	if _, err := os.Stat(filepath.Join(got, "events.hzn")); err != nil {
		t.Fatalf("cached file missing: %v", err)
	}
}

func TestFetchCacheKeyDerivedFromRepoSHA256(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	sum := sha256.Sum256([]byte(repo))
	want := hex.EncodeToString(sum[:])[:32]
	if got := cacheKey(repo); got != want {
		t.Fatalf("cacheKey(%q) = %q, want %q", repo, got, want)
	}
}

func TestFetchHonorsXDGCacheHome(t *testing.T) {
	override := t.TempDir()
	defer setCacheRoot(t, override)()
	got := cacheRoot()
	if got != override {
		t.Fatalf("cacheRoot() = %q, want %q", got, override)
	}
}

func TestFetchInvokesGitCloneOnCacheMiss(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	repo := "github.com/m31labs/horizon-test-events"
	ref := "v1.0.0"
	called := 0
	defer withGitCloneStub(t, func(gotRepo, gotRef, gotDest string) error {
		called++
		if gotRepo != "https://github.com/m31labs/horizon-test-events.git" {
			t.Errorf("clone repo = %q", gotRepo)
		}
		if gotRef != ref {
			t.Errorf("clone ref = %q, want %q", gotRef, ref)
		}
		// Simulate clone by populating dest.
		if err := os.MkdirAll(gotDest, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(gotDest, "events.hzn"), []byte("package events\n"), 0o644)
	})()
	got, diags, err := Fetch(repo, ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if called != 1 {
		t.Fatalf("gitClone called %d times, want 1", called)
	}
	want := filepath.Join(root, cacheKey(repo), ref)
	if got != want {
		t.Fatalf("Fetch returned %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(got, ".horizon-meta.json")); err != nil {
		t.Fatalf("meta file missing: %v", err)
	}
}

func TestFetchSurfacesGitErrorAsHZN1703(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	defer withGitCloneStub(t, func(_, _, _ string) error {
		return errors.New("simulated git failure: authentication denied")
	})()
	_, diags, err := Fetch("github.com/private/repo", "v1.0.0")
	if err != nil {
		t.Fatalf("Fetch returned hard error %v; want diagnostic only", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1703" {
			found = true
			if !strings.Contains(d.Message, "github.com/private/repo") {
				t.Errorf("HZN1703 message missing repo: %q", d.Message)
			}
		}
	}
	if !found {
		t.Fatalf("expected HZN1703 diagnostic, got %#v", diags)
	}
}

// writeCacheEntry materializes a single cache entry under root at
// <key>/<ref>/, optionally writing a .horizon-meta.json with the given
// fetchedAt. A zero fetchedAt skips the meta file entirely (simulating a
// half-written / legacy entry). Returns the leaf directory path.
func writeCacheEntry(t *testing.T, root, repo, ref string, fetchedAt time.Time, writeMeta bool) string {
	t.Helper()
	dir := filepath.Join(root, cacheKey(repo), ref)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	// A content file so the entry has a non-zero size.
	if err := os.WriteFile(filepath.Join(dir, "events.hzn"), []byte("package events\n"), 0o644); err != nil {
		t.Fatalf("WriteFile content: %v", err)
	}
	if writeMeta {
		meta := FetchMeta{
			SourceURL: repoURL(repo),
			Ref:       ref,
			FetchedAt: fetchedAt,
		}
		raw, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			t.Fatalf("MarshalIndent meta: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".horizon-meta.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("WriteFile meta: %v", err)
		}
	}
	return dir
}

func TestCacheEntriesReadsMeta(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	repo := "github.com/m31labs/horizon-test-events"
	ref := "v1.0.0"
	dir := writeCacheEntry(t, root, repo, ref, when, true)

	entries, err := CacheEntries()
	if err != nil {
		t.Fatalf("CacheEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Dir != dir {
		t.Errorf("Dir = %q, want %q", e.Dir, dir)
	}
	if !e.Meta.FetchedAt.Equal(when) {
		t.Errorf("Meta.FetchedAt = %v, want %v", e.Meta.FetchedAt, when)
	}
	if e.Meta.Ref != ref {
		t.Errorf("Meta.Ref = %q, want %q", e.Meta.Ref, ref)
	}
	if e.SizeBytes <= 0 {
		t.Errorf("SizeBytes = %d, want > 0", e.SizeBytes)
	}
}

func TestCacheEntriesHandlesMissingMeta(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	// Entry without a .horizon-meta.json (half-written / legacy).
	dir := writeCacheEntry(t, root, "github.com/m31labs/horizon-test-orphan", "v0.1.0", time.Time{}, false)

	entries, err := CacheEntries()
	if err != nil {
		t.Fatalf("CacheEntries returned hard error %v; missing meta must be tolerated", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Dir != dir {
		t.Errorf("Dir = %q, want %q", e.Dir, dir)
	}
	if !e.Meta.FetchedAt.IsZero() {
		t.Errorf("Meta.FetchedAt = %v, want zero (missing meta treated as oldest)", e.Meta.FetchedAt)
	}
	if e.SizeBytes <= 0 {
		t.Errorf("SizeBytes = %d, want > 0", e.SizeBytes)
	}
}

func TestCacheEntriesEmptyCache(t *testing.T) {
	root := t.TempDir()
	defer setCacheRoot(t, root)()
	entries, err := CacheEntries()
	if err != nil {
		t.Fatalf("CacheEntries on empty cache: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len(entries) = %d, want 0 for empty cache", len(entries))
	}
}

// withHTTPDiscoverStub swaps the package-level httpDiscover variable for
// the duration of a single test and resets the per-process discovery
// memo so each test starts from a clean cache. Returns a restore func to
// defer.
func withHTTPDiscoverStub(t *testing.T, stub func(host, path string) (string, error)) func() {
	t.Helper()
	prev := httpDiscover
	httpDiscover = stub
	resetCloneURLMemo()
	return func() {
		httpDiscover = prev
		resetCloneURLMemo()
	}
}

func TestResolveCloneURLGithubPassthrough(t *testing.T) {
	// github.com must NOT touch httpDiscover — it stays a pure repoURL
	// translation. Wire a stub that fails the test if called.
	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		t.Fatalf("httpDiscover called for github.com path (host=%q path=%q); github must stay pure", host, path)
		return "", nil
	})()
	got, diags := resolveCloneURL("github.com/m31labs/horizon-events")
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	want := "https://github.com/m31labs/horizon-events.git"
	if got != want {
		t.Fatalf("resolveCloneURL = %q, want %q", got, want)
	}
}

func TestResolveCloneURLMetaRedirect(t *testing.T) {
	const discovered = "https://github.com/m31labs/horizon-events.git"
	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		if host != "m31labs.dev" {
			t.Errorf("host = %q, want m31labs.dev", host)
		}
		if path != "m31labs/horizon-events" {
			t.Errorf("path = %q, want m31labs/horizon-events", path)
		}
		return discovered, nil
	})()
	got, diags := resolveCloneURL("m31labs.dev/m31labs/horizon-events")
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if got != discovered {
		t.Fatalf("resolveCloneURL = %q, want %q", got, discovered)
	}
}

func TestResolveCloneURLDiscoveryErrorEmitsHZN1705(t *testing.T) {
	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		return "", errors.New("simulated network failure: connection refused")
	})()
	got, diags := resolveCloneURL("m31labs.dev/m31labs/horizon-events")
	if got != "" {
		t.Errorf("resolveCloneURL returned URL %q on discovery failure, want empty", got)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1705" {
			found = true
			if !strings.Contains(d.Message, "m31labs.dev/m31labs/horizon-events") {
				t.Errorf("HZN1705 message missing import path: %q", d.Message)
			}
		}
	}
	if !found {
		t.Fatalf("expected HZN1705 diagnostic, got %#v", diags)
	}
}

func TestResolveCloneURLMemoizes(t *testing.T) {
	const discovered = "https://github.com/m31labs/horizon-events.git"
	calls := 0
	defer withHTTPDiscoverStub(t, func(host, path string) (string, error) {
		calls++
		return discovered, nil
	})()
	path := "m31labs.dev/m31labs/horizon-events"
	for i := 0; i < 3; i++ {
		got, diags := resolveCloneURL(path)
		if diag.HasErrors(diags) {
			t.Fatalf("iteration %d diagnostics = %#v", i, diags)
		}
		if got != discovered {
			t.Fatalf("iteration %d resolveCloneURL = %q, want %q", i, got, discovered)
		}
	}
	if calls != 1 {
		t.Fatalf("httpDiscover called %d times across 3 resolveCloneURL calls, want 1 (memoized)", calls)
	}
}

func TestRepoURLFromImportPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"github.com/m31labs/horizon-events", "https://github.com/m31labs/horizon-events.git"},
		{"github.com/foo/bar", "https://github.com/foo/bar.git"},
	}
	for _, c := range cases {
		if got := repoURL(c.path); got != c.want {
			t.Fatalf("repoURL(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
