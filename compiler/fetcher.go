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

// fetchMeta is the on-disk shape of `.horizon-meta.json`, written
// once per fresh cache entry. Lets a future `hzn cache prune` make
// informed eviction decisions without re-running git.
type fetchMeta struct {
	SourceURL string    `json:"source_url"`
	Ref       string    `json:"ref"`
	FetchedAt time.Time `json:"fetched_at"`
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
	meta := fetchMeta{
		SourceURL: url,
		Ref:       ref,
		FetchedAt: time.Now().UTC(),
	}
	if raw, err := json.MarshalIndent(meta, "", "  "); err == nil {
		// Best-effort — failing to write the metadata is not fatal
		// because the cached tree is still valid for resolution. The
		// only consequence is `hzn cache prune` (v0.3.1+) loses one
		// metadata record.
		_ = os.WriteFile(filepath.Join(dest, ".horizon-meta.json"), append(raw, '\n'), 0o644)
	}
	return dest, nil, nil
}
