package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"m31labs.dev/horizon/compiler/diag"
)

// sha256New returns a fresh sha256 hasher. Wrapped through a tiny
// helper so other compiler files that hash file trees can share one
// dependency surface instead of each importing crypto/sha256
// directly.
func sha256New() hash.Hash { return sha256.New() }

// sha256Hex returns the lowercase hex digest of h's accumulated state.
func sha256Hex(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// gitClone is the injection point for fetching a remote package. The
// production implementation shells out to `git clone --depth 1 --branch
// <ref>`; tests overwrite this variable to populate the cache without
// touching the network. Resolution flow: Fetch computes the cache
// destination, ensures the parent dir exists, then calls gitClone(repo,
// ref, dest). The stub or git binary is responsible for putting the
// package contents at dest.
var gitClone = func(repo, ref, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("prep cache parent %s: %w", filepath.Dir(dest), err)
	}
	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", ref, repo, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone %s @ %s: %v\n%s", repo, ref, err, string(out))
	}
	return nil
}

// cacheRoot returns the root directory under which fetched module
// contents are cached. Preference order:
//  1. $HORIZON_CACHE_ROOT (test + advanced-user override)
//  2. $XDG_CACHE_HOME/horizon/modules
//  3. $HOME/.cache/horizon/modules
//
// The override path is returned verbatim so tests can point at a
// fixture directory; the XDG / HOME paths get the canonical
// "horizon/modules" tail appended.
func cacheRoot() string {
	if root := os.Getenv("HORIZON_CACHE_ROOT"); root != "" {
		return root
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "horizon", "modules")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Last-ditch — relative cache; better than panicking.
		return filepath.Join(".horizon-cache", "modules")
	}
	return filepath.Join(home, ".cache", "horizon", "modules")
}

// cacheKey returns the on-disk cache directory name for a repo
// URL. The key is the first 32 hex chars of sha256(repo) — short
// enough to be ergonomic, long enough that practical collisions are
// essentially impossible across the package ecosystem.
//
// Keyed on the import path (not the resolved HTTPS URL) so the same
// `github.com/foo/bar` import resolves to the same cache slot
// regardless of how the resolver later spells the clone URL.
func cacheKey(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return hex.EncodeToString(sum[:])[:32]
}

// repoURL translates an import-path-shaped repo identifier into a
// clone URL. Today only github.com is supported directly — that
// covers the entire v0.3 surface. Other shapes flow through the
// vendor walk and never reach Fetch.
func repoURL(importPath string) string {
	if strings.HasPrefix(importPath, "github.com/") {
		return "https://" + importPath + ".git"
	}
	// Fallback: assume https scheme. Reachable only via direct
	// `Fetch(...)` calls; the resolver gates on github.com before
	// invoking us in v0.3.
	return "https://" + importPath
}

// FetchMeta is the on-disk shape of `.horizon-meta.json`, written
// once per fresh cache entry. It lets `hzn cache prune` make informed
// eviction decisions (by age / LRU) without re-running git. Exported
// so the `cmd/hzn` cache subcommand reads the schema from one place
// rather than re-declaring it.
type FetchMeta struct {
	SourceURL string    `json:"source_url"`
	Ref       string    `json:"ref"`
	FetchedAt time.Time `json:"fetched_at"`
}

// CacheEntry is one content-addressed module-cache entry: the leaf
// directory under cacheRoot()/<key>/<ref>/, its decoded FetchMeta, and
// the non-recursive byte size of the files directly under Dir. An entry
// whose `.horizon-meta.json` is missing or corrupt yields a zero-value
// Meta (in particular a zero Meta.FetchedAt), which prune treats as
// "oldest" / always-evictable rather than a hard error.
type CacheEntry struct {
	Dir       string
	Meta      FetchMeta
	SizeBytes int64
}

// CacheEntries walks the content-addressed module cache and returns one
// CacheEntry per <key>/<ref> leaf directory. The cache layout mirrors
// Fetch's destination: cacheRoot()/<cacheKey>/<ref>/. A non-existent
// cache root is not an error — it yields an empty slice (nothing cached
// yet). A missing/corrupt per-entry meta is tolerated: the entry is
// still returned with a zero-value Meta so it remains prunable.
func CacheEntries() ([]CacheEntry, error) {
	root := cacheRoot()
	keyDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache root %s: %w", root, err)
	}
	var entries []CacheEntry
	for _, kd := range keyDirs {
		if !kd.IsDir() {
			continue
		}
		keyPath := filepath.Join(root, kd.Name())
		refDirs, err := os.ReadDir(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read cache key dir %s: %w", keyPath, err)
		}
		for _, rd := range refDirs {
			if !rd.IsDir() {
				continue
			}
			dir := filepath.Join(keyPath, rd.Name())
			meta := readFetchMeta(dir)
			size, err := entryDirSize(dir)
			if err != nil {
				return nil, fmt.Errorf("size cache entry %s: %w", dir, err)
			}
			entries = append(entries, CacheEntry{Dir: dir, Meta: meta, SizeBytes: size})
		}
	}
	return entries, nil
}

// readFetchMeta loads the `.horizon-meta.json` from a cache entry
// directory. A missing or unparseable file yields a zero-value FetchMeta
// (no error) so a half-written entry stays prunable.
func readFetchMeta(dir string) FetchMeta {
	raw, err := os.ReadFile(filepath.Join(dir, ".horizon-meta.json"))
	if err != nil {
		return FetchMeta{}
	}
	var meta FetchMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return FetchMeta{}
	}
	return meta
}

// entryDirSize sums the sizes of the regular files directly under dir
// (non-recursive — O-C2 default). Each cache entry is a flat package
// tree, so a non-recursive sum is a faithful, cheap proxy for the
// entry's footprint.
func entryDirSize(dir string) (int64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// Fetch ensures the package at <repo>@<ref> is present in the
// content-addressed cache and returns its directory path. A cache
// hit (dest already exists) short-circuits the git invocation
// entirely — gitClone is not called. On a miss, gitClone is
// invoked; success writes a `.horizon-meta.json` record next to the
// cloned tree.
//
// Errors from gitClone are surfaced as HZN1703 diagnostics rather
// than hard errors so callers can collect them alongside other
// resolution diagnostics. A non-nil error is returned only for I/O
// failures inside the cache-root setup (e.g. permission denied
// creating the cache dir).
func Fetch(repo, ref string) (string, []diag.Diagnostic, error) {
	dest := filepath.Join(cacheRoot(), cacheKey(repo), ref)
	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		// Cache hit. Skip git entirely; trust the on-disk content.
		// sha256 verification happens at the resolver layer against
		// the lockfile entry — not here, because Fetch has no
		// knowledge of what content is "expected".
		return dest, nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", nil, fmt.Errorf("prep cache parent %s: %w", filepath.Dir(dest), err)
	}
	url := repoURL(repo)
	if err := gitClone(url, ref, dest); err != nil {
		return "", []diag.Diagnostic{{
			Code:     "HZN1703",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("fetch failed for %s @ %s: %v", repo, ref, err),
			Suggest:  "check the repository URL, the ref (tag or SHA), and your git credentials; for offline builds, vendor the package under ./vendor/<path>/",
		}}, nil
	}
	meta := FetchMeta{
		SourceURL: url,
		Ref:       ref,
		FetchedAt: time.Now().UTC(),
	}
	if raw, err := json.MarshalIndent(meta, "", "  "); err == nil {
		// Best-effort — failing to write the metadata is not fatal
		// because the cached tree is still valid for resolution. The
		// only consequence is `hzn cache prune` loses one metadata
		// record (CacheEntries tolerates the gap with a zero-value
		// FetchMeta, treating the entry as oldest / always-prunable).
		_ = os.WriteFile(filepath.Join(dest, ".horizon-meta.json"), append(raw, '\n'), 0o644)
	}
	return dest, nil, nil
}
