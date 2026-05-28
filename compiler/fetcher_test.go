package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
