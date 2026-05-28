package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

// runGet implements `hzn get <repo>@<ref> [path]` — the v0.3 add-a-
// remote-dep workflow (roadmap #14). The command:
//
//  1. Parses `<repo>@<ref>` from the first positional argument.
//  2. Synthesizes a transient import-only .hzn file in the build dir
//     so the resolver's normal lockfile-update mode picks it up.
//  3. Runs the resolver in lockfile-update mode.
//  4. Merges the resulting LockfileEntry into the existing hzn.lock
//     (or creates one) and writes it atomically.
//
// On success the user sees "added <path>@<version> -> <ref> (sha256
// <prefix>...)" on stderr and exits 0. Resolution failures (bad
// version syntax, fetch errors, etc.) surface as the same
// diagnostics `hzn check` would show.
func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: hzn get <repo>@<version> [path]")
	}
	spec := fs.Arg(0)
	at := strings.LastIndex(spec, "@")
	if at <= 0 || at == len(spec)-1 {
		return fmt.Errorf("invalid spec %q: expected <repo>@<version>", spec)
	}
	repo, version := spec[:at], spec[at+1:]

	buildRoot := "."
	if fs.NArg() >= 2 {
		buildRoot = fs.Arg(1)
	}
	absRoot, err := filepath.Abs(buildRoot)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", buildRoot, err)
	}
	if info, err := os.Stat(absRoot); err != nil || !info.IsDir() {
		return fmt.Errorf("build root %s is not a directory: %v", absRoot, err)
	}

	// Synthesize a one-line import-only .hzn file so the resolver
	// sees the requested dep without us reinventing parsing.
	// Removed in a defer so the build dir stays clean.
	stub := filepath.Join(absRoot, ".hzn-get-stub.hzn")
	stubBody := fmt.Sprintf("package _hzn_get_stub\n\nimport _ \"%s@%s\"\n", repo, version)
	if err := os.WriteFile(stub, []byte(stubBody), 0o644); err != nil {
		return fmt.Errorf("write stub: %w", err)
	}
	defer os.Remove(stub)

	res, err := compiler.ResolveImportsOpts(absRoot, compiler.ResolveOpts{
		LockfileUpdate: true,
	})
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	// Surface diagnostics on stderr in the same shape `hzn check`
	// does — the resolver is what flags HZN1704 (bad version) and
	// HZN1703 (fetch failure).
	for _, d := range res.Diagnostics {
		fmt.Fprintln(os.Stderr, formatDiagnostic(d))
	}
	if diag.HasErrors(res.Diagnostics) {
		return fmt.Errorf("hzn get failed; see diagnostics above")
	}
	if len(res.LockfileUpdate) == 0 {
		// Either the dep was already pinned (in which case no
		// update is required) or the resolver short-circuited.
		fmt.Fprintf(os.Stderr, "hzn get: %s@%s already pinned in hzn.lock — no changes\n", repo, version)
		return nil
	}

	// Merge into existing lockfile (load → upsert → save).
	lf, _, err := compiler.LoadLockfile(absRoot)
	if err != nil {
		return fmt.Errorf("load existing lockfile: %w", err)
	}
	for _, add := range res.LockfileUpdate {
		lf = upsertLockfileEntry(lf, add)
	}
	if err := compiler.SaveLockfile(absRoot, lf); err != nil {
		return fmt.Errorf("write lockfile: %w", err)
	}
	for _, add := range res.LockfileUpdate {
		shaPrefix := add.SHA256
		if len(shaPrefix) > 12 {
			shaPrefix = shaPrefix[:12]
		}
		fmt.Fprintf(os.Stderr, "hzn get: added %s@%s -> %s (sha256 %s...)\n",
			add.Path, add.Version, add.RefResolved, shaPrefix)
	}
	return nil
}

// upsertLockfileEntry replaces an existing entry for add.Path or
// appends add when no entry exists. Sorting is handled by
// compiler.SaveLockfile on write.
func upsertLockfileEntry(lf compiler.Lockfile, add compiler.LockfileEntry) compiler.Lockfile {
	for i, e := range lf.Entries {
		if e.Path == add.Path {
			lf.Entries[i] = add
			return lf
		}
	}
	lf.Entries = append(lf.Entries, add)
	return lf
}

// formatDiagnostic renders one diagnostic as a single line for
// stderr — minimal because `hzn get` is a small ceremony command
// (not a long-form linter like `hzn check`).
func formatDiagnostic(d diag.Diagnostic) string {
	prefix := "error"
	if d.Severity == diag.SeverityWarning {
		prefix = "warning"
	}
	out := fmt.Sprintf("%s: %s: %s", prefix, d.Code, d.Message)
	if d.Suggest != "" {
		out += "\n  suggest: " + d.Suggest
	}
	return out
}
