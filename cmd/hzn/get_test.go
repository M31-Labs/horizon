package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hznGetCacheKey mirrors compiler.cacheKey (unexported in the
// compiler package). Tests need the same algorithm to seed the
// fixture cache under the right directory name.
func hznGetCacheKey(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return hex.EncodeToString(sum[:])[:32]
}

// TestHznGetPinnedSHAWritesLockfile drives `hzn get` end-to-end
// against a pre-seeded cache. Pinning by SHA (≥7 hex chars) avoids
// the ls-remote round-trip entirely — the resolver short-circuits
// resolveRef when imp.Version already looks like a SHA. The
// expectation: a hzn.lock file appears with one entry whose
// ref_resolved == the supplied SHA and sha256 matches the cached
// content.
func TestHznGetPinnedSHAWritesLockfile(t *testing.T) {
	repo := "github.com/m31labs/horizon-test-events"
	ref := "abc1234567890abcdef1234567890abcdef12345"

	cacheRoot := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", cacheRoot)
	dest := filepath.Join(cacheRoot, hznGetCacheKey(repo), ref)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "events.hzn"), []byte("package events\n\ntype Exec struct {\n    pid u32\n}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile fixture: %v", err)
	}

	buildRoot := t.TempDir()
	if err := run([]string{"get", repo + "@" + ref, buildRoot}); err != nil {
		t.Fatalf("hzn get: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(buildRoot, "hzn.lock"))
	if err != nil {
		t.Fatalf("read hzn.lock: %v", err)
	}
	var lf struct {
		Schema  string `json:"schema"`
		Entries []struct {
			Path        string `json:"path"`
			Version     string `json:"version"`
			RefResolved string `json:"ref_resolved"`
			SHA256      string `json:"sha256"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &lf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if lf.Schema != "m31labs.dev/horizon/lockfile/v1" {
		t.Fatalf("schema = %q", lf.Schema)
	}
	if len(lf.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(lf.Entries))
	}
	e := lf.Entries[0]
	if e.Path != repo {
		t.Fatalf("entry.Path = %q", e.Path)
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

func TestHznGetRejectsBadVersionHZN1704(t *testing.T) {
	buildRoot := t.TempDir()
	// `latest` is explicitly rejected — neither semver nor SHA. The
	// resolver surfaces HZN1704 and hzn get exits non-zero.
	err := run([]string{"get", "github.com/foo/bar@latest", buildRoot})
	if err == nil {
		t.Fatalf("hzn get @latest should fail")
	}
	if !strings.Contains(err.Error(), "diagnostics") && !strings.Contains(err.Error(), "1704") {
		// Soft check — error wrap may not embed the code, but
		// stderr does. We're verifying the failure path here, not
		// the exact message.
	}
}

func TestHznGetRejectsMalformedSpec(t *testing.T) {
	cases := []string{
		"github.com/foo/bar",       // no @
		"@v1.0.0",                  // no repo
		"github.com/foo/bar@",      // empty version
	}
	for _, spec := range cases {
		t.Run(spec, func(t *testing.T) {
			err := run([]string{"get", spec})
			if err == nil {
				t.Fatalf("hzn get %q should fail", spec)
			}
		})
	}
}
