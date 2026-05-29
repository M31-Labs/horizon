package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/horizon/compiler"
)

// seedCacheEntry writes one cache entry at <root>/<key>/<ref>/ with a
// content file and a `.horizon-meta.json` carrying fetchedAt. The key
// can be any directory name — CacheEntries walks the two-level
// <key>/<ref> layout without re-deriving the sha256 cache key. Returns
// the leaf directory.
func seedCacheEntry(t *testing.T, root, key, ref string, fetchedAt time.Time, sizeFill int) string {
	t.Helper()
	dir := filepath.Join(root, key, ref)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	if sizeFill <= 0 {
		sizeFill = 16
	}
	body := make([]byte, sizeFill)
	for i := range body {
		body[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(dir, "events.hzn"), body, 0o644); err != nil {
		t.Fatalf("WriteFile content: %v", err)
	}
	meta := compiler.FetchMeta{
		SourceURL: "https://" + key + ".example/repo.git",
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
	return dir
}

// dirExists reports whether path is an existing directory.
func dirExists(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func TestCachePruneOlderThanEvictsAgedEntries(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	now := time.Now().UTC()
	old := seedCacheEntry(t, root, "key-old", "v1.0.0", now.Add(-72*time.Hour), 32)
	fresh := seedCacheEntry(t, root, "key-fresh", "v2.0.0", now.Add(-1*time.Hour), 32)

	if err := runCache([]string{"prune", "-older-than", "24h"}); err != nil {
		t.Fatalf("runCache prune -older-than: %v", err)
	}
	if dirExists(t, old) {
		t.Errorf("aged entry %q should have been evicted", old)
	}
	if !dirExists(t, fresh) {
		t.Errorf("fresh entry %q should have survived", fresh)
	}
}

func TestCachePruneMaxSizeEvictsLRU(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	now := time.Now().UTC()
	// Three equal-sized entries; oldest first by FetchedAt. Each entry's
	// on-disk size is content + the .horizon-meta.json, so derive the
	// budget from the actual measured size rather than hard-coding it:
	// a budget that fits two entries but not three forces eviction of
	// exactly the oldest.
	oldest := seedCacheEntry(t, root, "key-a", "v1.0.0", now.Add(-72*time.Hour), 100)
	middle := seedCacheEntry(t, root, "key-b", "v2.0.0", now.Add(-48*time.Hour), 100)
	newest := seedCacheEntry(t, root, "key-c", "v3.0.0", now.Add(-1*time.Hour), 100)

	entries, err := compiler.CacheEntries()
	if err != nil {
		t.Fatalf("CacheEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("seeded %d entries, want 3", len(entries))
	}
	per := entries[0].SizeBytes
	// Budget holds exactly two entries (2*per) but not three, so only
	// the single oldest entry is evicted.
	budget := 2*per + per/2

	if err := runCache([]string{"prune", "-max-size", fmt.Sprintf("%d", budget)}); err != nil {
		t.Fatalf("runCache prune -max-size: %v", err)
	}
	if dirExists(t, oldest) {
		t.Errorf("oldest entry %q should be evicted under LRU budget", oldest)
	}
	if !dirExists(t, middle) {
		t.Errorf("middle entry %q should survive (within budget after evicting oldest)", middle)
	}
	if !dirExists(t, newest) {
		t.Errorf("newest entry %q should survive", newest)
	}
}

func TestCachePruneDryRunDeletesNothing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	now := time.Now().UTC()
	old := seedCacheEntry(t, root, "key-old", "v1.0.0", now.Add(-72*time.Hour), 32)

	if err := runCache([]string{"prune", "-older-than", "24h", "-dry-run"}); err != nil {
		t.Fatalf("runCache prune dry-run: %v", err)
	}
	if !dirExists(t, old) {
		t.Errorf("dry-run must not delete entry %q", old)
	}
}

func TestCachePruneNoFlagsListsOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	now := time.Now().UTC()
	a := seedCacheEntry(t, root, "key-a", "v1.0.0", now.Add(-72*time.Hour), 32)
	b := seedCacheEntry(t, root, "key-b", "v2.0.0", now.Add(-1*time.Hour), 32)

	// Bare `prune` with no policy flag must be non-destructive.
	if err := runCache([]string{"prune"}); err != nil {
		t.Fatalf("runCache prune (no flags): %v", err)
	}
	if !dirExists(t, a) || !dirExists(t, b) {
		t.Errorf("bare prune must not delete anything (a=%v b=%v)", dirExists(t, a), dirExists(t, b))
	}
}

func TestCachePruneEmptyCacheNoOp(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HORIZON_CACHE_ROOT", root)
	// No entries seeded; both prune and the default list path must be
	// clean no-ops.
	if err := runCache([]string{"prune", "-older-than", "24h"}); err != nil {
		t.Fatalf("runCache prune on empty cache: %v", err)
	}
	if err := runCache([]string{"list"}); err != nil {
		t.Fatalf("runCache list on empty cache: %v", err)
	}
	if err := runCache(nil); err != nil {
		t.Fatalf("runCache (no args) on empty cache: %v", err)
	}
}
