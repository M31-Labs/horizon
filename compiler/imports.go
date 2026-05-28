package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/parser"
)

// ImportGraph carries the cross-package resolution state collected by
// ResolveImports. Edges is keyed by importer-package directory (canonical
// absolute path) → alias → resolved-path. For builtin imports the resolved
// value is the canonical builtin path string (e.g.
// "m31labs.dev/horizon/runtime/kernel"); for filesystem imports it is the
// directory the foreign package's .hzn files live under. BuiltinAliases is the
// union of all aliases that resolve to compiler-builtin namespaces; the type
// checker consults this set to keep selector references like `bpf.foo` routed
// through the existing hardcoded namespace path instead of looking the alias
// up in the user-package index.
type ImportGraph struct {
	Edges          map[string]map[string]string
	Packages       map[string]ast.Package
	BuiltinAliases map[string]bool
}

// PackageRoot is the on-disk root of one package — a directory containing one
// or more sibling .hzn files that share a `package <name>` declaration.
type PackageRoot struct {
	Dir   string
	Name  string
	Files []ast.File
	Edges []ast.ImportEdge
}

// builtinImportPaths is the canonical set of import paths that resolve to a
// compiler-builtin namespace rather than walking the filesystem. The mapping
// is path → canonical namespace name. Any alias may bind a builtin path
// (per plan O-2): `import bpf "…/kernel"` and `import bee "…/kernel"` are
// both legal and both route the alias to the kernel builtin namespace.
var builtinImportPaths = map[string]string{
	"m31labs.dev/horizon/runtime/kernel":     "bpf",
	"m31labs.dev/horizon/runtime/xdp":        "xdp",
	"m31labs.dev/horizon/runtime/tc":         "tc",
	"m31labs.dev/horizon/runtime/cgroup":     "cgroup",
	"m31labs.dev/horizon/runtime/lsm":        "lsm",
	"m31labs.dev/horizon/runtime/kprobe":     "kprobe",
	"m31labs.dev/horizon/runtime/kretprobe":  "kretprobe",
	"m31labs.dev/horizon/runtime/tracepoint": "tracepoint",
}

// ResolveImports walks every .hzn file under rootDir, parses each file's
// import declarations, and resolves each import to either (a) a compiler
// builtin namespace, (b) a relative directory, (c) an absolute filesystem
// path (with HZN1556 warning), (d) a remote URL with `@version` resolved
// via hzn.lock + content-addressed cache (roadmap #14), or (e) a vendored
// package directory found by walking parent dirs for `vendor/<full-path>/`.
// Unresolved imports produce HZN1554; import cycles produce HZN1555.
//
// The return shape is: the root package (the one declared inside rootDir), a
// slice of dependency packages (transitively reached), the resolved graph
// linking aliases to packages, and the accumulated diagnostics. err is
// non-nil only for hard I/O failures — resolution failures are surfaced via
// diags.
func ResolveImports(rootDir string) (root ast.Package, deps []ast.Package, graph ImportGraph, diags []diag.Diagnostic, err error) {
	return ResolveImportsCtx(rootDir, DetectContext())
}

// ResolveImportsCtx is the build-context-aware form of ResolveImports.
// Files carrying `//hzn:build <expr>` directives are filtered against
// ctx before parsing; only surviving files contribute to the returned
// packages. When every file in a *reached* package directory is
// excluded by the filter, diagnostic HZN1680 fires.
//
// Most callers use ResolveImports, which delegates here with
// DetectContext(). Tests that need a deterministic context (e.g. the
// `multifile-buildtag` golden fixture) call ResolveImportsCtx directly
// or set the per-dimension HORIZON_BUILD_* env vars and reset the
// DetectContext cache via resetContextCache.
func ResolveImportsCtx(rootDir string, ctx BuildContext) (root ast.Package, deps []ast.Package, graph ImportGraph, diags []diag.Diagnostic, err error) {
	res, err := ResolveImportsOpts(rootDir, ResolveOpts{Ctx: ctx})
	if err != nil {
		return res.Root, res.Deps, res.Graph, res.Diagnostics, err
	}
	return res.Root, res.Deps, res.Graph, res.Diagnostics, nil
}

// ResolveOpts carries the configurable resolver knobs introduced in
// roadmap #14. Zero-value Opts (Ctx == zero, LockfileUpdate == false)
// match the legacy ResolveImportsCtx behavior exactly — every existing
// caller continues to work without modification. Callers that want
// `hzn get`-style behavior (resolve a `@version` to a SHA and append
// to LockfileUpdate instead of erroring HZN1701) pass LockfileUpdate
// = true.
type ResolveOpts struct {
	// Ctx is the build context filter applied to `//hzn:build`
	// directives. Empty value means use DetectContext().
	Ctx BuildContext
	// LockfileUpdate switches the resolver from verify-only mode to
	// write-back mode. When true: a remote import whose lockfile
	// entry is missing triggers resolution (via resolveRef + Fetch),
	// the resulting entry is appended to ResolveResult.LockfileUpdate
	// for the caller to persist, and HZN1701 is suppressed.
	LockfileUpdate bool
}

// ResolveResult is the aggregate output of ResolveImportsOpts. The
// first three fields mirror the legacy 5-tuple shape; LockfileUpdate
// is the new accumulator populated only in LockfileUpdate mode (one
// entry per remote import that wasn't already pinned).
type ResolveResult struct {
	Root           ast.Package
	Deps           []ast.Package
	Graph          ImportGraph
	Diagnostics    []diag.Diagnostic
	LockfileUpdate []LockfileEntry
}

// resolveRef maps a (repoURL, version) pair to a full 40-char git
// SHA. Production implementation shells out to `git ls-remote`; tests
// override the var to return a deterministic SHA without touching the
// network. Returns "" with a nil error if the version can't be
// resolved (which the caller then surfaces as a diagnostic).
var resolveRef = func(repoURL, version string) (string, error) {
	// Naive production implementation — sufficient for v0.3. A
	// `git ls-remote <url> <version>` returns "<sha>\trefs/tags/<v>"
	// for a tag or "<sha>\trefs/heads/<v>" for a branch. We accept
	// either match.
	cmd := exec.Command("git", "ls-remote", repoURL, "refs/tags/"+version, "refs/heads/"+version, version)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 && len(parts[0]) == 40 {
			return parts[0], nil
		}
	}
	return "", nil
}

// ResolveImportsOpts is the options-bearing form of ResolveImports
// added for roadmap #14. It threads a ResolveOpts through the
// resolver so callers (notably `hzn get`) can switch between
// verify-only mode and lockfile-update mode without forking the
// resolution code path. The legacy ResolveImports / ResolveImportsCtx
// signatures delegate here with zero-value opts.
func ResolveImportsOpts(rootDir string, opts ResolveOpts) (ResolveResult, error) {
	ctx := opts.Ctx
	if ctx == (BuildContext{}) {
		ctx = DetectContext()
	}
	root, deps, graph, diags, lfu, err := resolveImportsInternal(rootDir, ctx, opts.LockfileUpdate)
	return ResolveResult{
		Root:           root,
		Deps:           deps,
		Graph:          graph,
		Diagnostics:    diags,
		LockfileUpdate: lfu,
	}, err
}

func resolveImportsInternal(rootDir string, ctx BuildContext, lockfileUpdate bool) (root ast.Package, deps []ast.Package, graph ImportGraph, diags []diag.Diagnostic, lfu []LockfileEntry, err error) {
	graph.Edges = map[string]map[string]string{}
	graph.Packages = map[string]ast.Package{}
	graph.BuiltinAliases = map[string]bool{}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return ast.Package{}, nil, graph, nil, nil, fmt.Errorf("resolve absolute path for %s: %w", rootDir, err)
	}

	// AnalyzePath accepts both a directory and a single .hzn file. If the
	// caller pointed at a file, treat its parent directory as the build root
	// but only load that one file into the root package — sibling files in
	// the same directory may belong to a different test fixture.
	var singleFile string
	if info, statErr := os.Stat(absRoot); statErr == nil && !info.IsDir() {
		singleFile = absRoot
		absRoot = filepath.Dir(absRoot)
	}

	// Load hzn.lock once per resolution pass. Missing file is fine —
	// only remote imports require an entry. Schema mismatch surfaces
	// as HZN1702 here (folded into the result diagnostics so the
	// caller sees them with the same shape as any other resolution
	// error).
	lockfile, lockDiags, lerr := LoadLockfile(absRoot)
	if lerr != nil {
		return ast.Package{}, nil, graph, nil, nil, lerr
	}
	diags = append(diags, lockDiags...)

	// remoteSeen prevents emitting two HZN1700/HZN1701 diagnostics
	// for the same import path if the same remote dep is imported
	// from multiple files in the build. Also dedupes LockfileUpdate
	// entries.
	remoteSeen := map[string]bool{}

	// Visited state for DFS / cycle detection. Keys are canonical absolute
	// directory paths. addedToDeps tracks whether a non-root package has been
	// emitted into the deps slice, so transitive packages reached via shared
	// branches still surface exactly once.
	onStack := map[string]bool{}
	addedToDeps := map[string]bool{}

	var visit func(dir string, importSpan span.Span, singlePath string) (ast.Package, []diag.Diagnostic, error)
	visit = func(dir string, importSpan span.Span, singlePath string) (ast.Package, []diag.Diagnostic, error) {
		if onStack[dir] {
			d := diag.Diagnostic{
				Code:     "HZN1555",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("import cycle detected at package directory %s", dir),
				Primary:  importSpan,
				Suggest:  "remove the cycle by introducing a shared package both ends can import, or by inverting the dependency direction",
			}
			return ast.Package{}, []diag.Diagnostic{d}, nil
		}
		if pkg, ok := graph.Packages[dir]; ok {
			return pkg, nil, nil
		}
		onStack[dir] = true
		defer func() { onStack[dir] = false }()

		pkg, ds, err := loadPackage(dir, singlePath, ctx)
		if err != nil {
			return ast.Package{}, ds, err
		}

		// HZN1680: if a non-root package was reached from an import but
		// every one of its `.hzn` files was filtered out by the active
		// build constraints, the package is unreachable under this
		// context. Fires only for imported packages — a root with no
		// surviving files flows through the existing "no .hzn files"
		// path. Source-on-disk vs filtered-out is distinguished by
		// dirHasHznFiles (would be true here even when pkg.Files is
		// empty).
		if dir != absRoot && len(pkg.Files) == 0 && dirHasHznFiles(dir) {
			ds = append(ds, diag.Diagnostic{
				Code:     "HZN1680",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("build constraint excluded all files in package %q", dir),
				Primary:  importSpan,
				Suggest:  "remove a `//hzn:build` directive from at least one file, or adjust the active build context (HORIZON_BUILD_OS / _ARCH / _KERNEL / _BTF) so at least one constraint evaluates true",
			})
		}

		// Resolve each import in each file.
		seenAlias := map[string]bool{}
		for _, f := range pkg.Files {
			for _, imp := range f.Imports {
				if seenAlias[imp.Alias] {
					// HZN1551 is the dup-alias code; for this task the
					// resolver simply records the first binding and skips
					// reprocessing. The dedicated diagnostic surfaces in
					// Subtask 3a (types layer) per the plan.
					continue
				}
				seenAlias[imp.Alias] = true
				edge, depPkg, depDiags, addLock, derr := resolveOne(dir, absRoot, imp, resolveState{
					Lockfile:       lockfile,
					LockfileUpdate: lockfileUpdate,
					RemoteSeen:     remoteSeen,
				}, func(d string, s span.Span) (ast.Package, []diag.Diagnostic, error) {
					return visit(d, s, "")
				})
				ds = append(ds, depDiags...)
				if addLock != nil {
					lfu = append(lfu, *addLock)
				}
				if derr != nil {
					return ast.Package{}, ds, derr
				}
				pkg.ImportEdges = append(pkg.ImportEdges, edge)
				if graph.Edges[dir] == nil {
					graph.Edges[dir] = map[string]string{}
				}
				graph.Edges[dir][imp.Alias] = edge.ResolvedPath
				if edge.Builtin {
					graph.BuiltinAliases[imp.Alias] = true
					continue
				}
				// An import alias that shadows a hardcoded compiler namespace
				// (`import bpf "./mything"`) extends HZN1004 — the same code
				// types/checker.go uses for top-level declarations colliding
				// with bpf/xdp/tc/etc. The check fires only for non-builtin
				// imports because builtin paths intentionally accept any
				// alias (per plan O-2: `import bee "…/kernel"` is legal).
				// (roadmap #20 Phase 2 Subtask 6c.)
				if isCompilerNamespaceName(imp.Alias) {
					ds = append(ds, diag.Diagnostic{
						Code:     "HZN1004",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("import alias %q conflicts with a compiler namespace", imp.Alias),
						Primary:  imp.Span,
						Suggest:  "compiler namespaces such as bpf, xdp, tc, cgroup, lsm, kprobe, kretprobe, and tracepoint are reserved; rename the alias on this import",
					})
				}
				if depPkg.Name == "" {
					continue
				}
				if !addedToDeps[edge.ResolvedPath] {
					addedToDeps[edge.ResolvedPath] = true
					deps = append(deps, depPkg)
				}
			}
		}
		graph.Packages[dir] = pkg
		return pkg, ds, nil
	}

	root, rootDiags, rerr := visit(absRoot, span.Span{File: span.FileID(absRoot)}, singleFile)
	diags = append(diags, rootDiags...)
	if rerr != nil {
		return root, deps, graph, diags, lfu, rerr
	}
	return root, deps, graph, diags, lfu, nil
}

// resolveState is the per-resolution-pass state threaded through
// resolveOne. It carries the loaded lockfile (consulted for remote
// imports), the lockfile-update flag (toggles HZN1701 vs lockfile
// write-back behavior), and a dedupe set so repeat imports of the
// same remote dep don't emit duplicate diagnostics or
// LockfileUpdate entries.
type resolveState struct {
	Lockfile       Lockfile
	LockfileUpdate bool
	RemoteSeen     map[string]bool
}

// resolveOne maps a single ast.ImportDecl to a resolved package directory (or
// a builtin stub). The resolution order mirrors the plan's §Import shape:
//  1. exact match against builtinImportPaths
//  2. relative path (./, ../)
//  3. absolute path (warn HZN1556)
//  4. remote URL with `@<version>` — lockfile lookup + content-addressed
//     cache (roadmap #14)
//  5. vendor walk for URL-shaped paths
//  6. not-found → HZN1554
//
// The fourth (remote) mode short-circuits before the vendor walk so a
// project that has both a pinned remote import and a stale vendor/
// directory consistently picks the lockfile entry. Vendoring remains the
// resolution path for URL-shaped imports without `@version`.
func resolveOne(
	currentDir, buildRoot string,
	imp ast.ImportDecl,
	state resolveState,
	visit func(dir string, importSpan span.Span) (ast.Package, []diag.Diagnostic, error),
) (ast.ImportEdge, ast.Package, []diag.Diagnostic, *LockfileEntry, error) {
	edge := ast.ImportEdge{Alias: imp.Alias, Span: imp.Span}

	// 1. Builtin.
	if _, ok := builtinImportPaths[imp.Path]; ok {
		edge.ResolvedPath = imp.Path
		edge.Builtin = true
		return edge, ast.Package{}, nil, nil, nil
	}

	// 2. Relative.
	if strings.HasPrefix(imp.Path, "./") || strings.HasPrefix(imp.Path, "../") {
		abs, err := filepath.Abs(filepath.Join(currentDir, imp.Path))
		if err != nil {
			return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, err.Error())}, nil, nil
		}
		if !dirHasHznFiles(abs) {
			return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, abs)}, nil, nil
		}
		edge.ResolvedPath = abs
		dep, ds, err := visit(abs, imp.Span)
		return edge, dep, ds, nil, err
	}

	// 3. Absolute filesystem path.
	if strings.HasPrefix(imp.Path, "/") {
		warn := diag.Diagnostic{
			Code:     "HZN1556",
			Severity: diag.SeverityWarning,
			Message:  fmt.Sprintf("absolute import path %q is not portable across machines", imp.Path),
			Primary:  imp.Span,
			Suggest:  "use a relative path (./foo) or a vendored URL-shaped path resolved via vendor/",
		}
		if !dirHasHznFiles(imp.Path) {
			return edge, ast.Package{}, []diag.Diagnostic{warn, importNotFoundDiag(imp, imp.Path)}, nil, nil
		}
		edge.ResolvedPath = imp.Path
		dep, ds, err := visit(imp.Path, imp.Span)
		return edge, dep, append([]diag.Diagnostic{warn}, ds...), nil, err
	}

	// 4. Remote import — URL-shaped path with `@<version>` suffix.
	// Only `github.com/<org>/<repo>` direct shape is wired in v0.3;
	// m31labs.dev meta-redirect is documented but stub-only (resolves
	// to HZN1554 if no vendor entry exists, per the decision memo).
	if imp.Version != "" && isRemoteImportShape(imp.Path) {
		dep, ds, addLock, err := resolveRemote(imp, state, visit)
		// resolveRemote sets edge.ResolvedPath via the visit
		// closure; bubble it through here too for the alias index.
		if addLock != nil && dep.Name != "" {
			// Resolved successfully — set the edge's resolved path
			// to the cache dest so graph.Edges records it.
			edge.ResolvedPath = filepath.Join(cacheRoot(), cacheKey(imp.Path), addLock.RefResolved)
		} else if dep.Name != "" {
			// Verify mode (lockfile entry existed) — derive edge path
			// from the lockfile entry's resolved ref.
			if entry, ok := state.Lockfile.LookupEntry(imp.Path); ok {
				edge.ResolvedPath = filepath.Join(cacheRoot(), cacheKey(imp.Path), entry.RefResolved)
			}
		}
		return edge, dep, ds, addLock, err
	}

	// 5. URL-shaped vendored path. Walk parent directories looking for the
	// nearest `vendor/<full-path>/` rooted at or above currentDir; never walk
	// above buildRoot.
	dir := currentDir
	for {
		candidate := filepath.Join(dir, "vendor", filepath.FromSlash(imp.Path))
		if dirHasHznFiles(candidate) {
			edge.ResolvedPath = candidate
			dep, ds, err := visit(candidate, imp.Span)
			return edge, dep, ds, nil, err
		}
		if dir == buildRoot {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// 6. Not found.
	return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, imp.Path)}, nil, nil
}

// isRemoteImportShape reports whether imp.Path looks like a remote
// repository identifier we know how to fetch. v0.3 only wires
// github.com directly; other hosts fall through to the vendor walk.
// Keep this conservative — broadening the set later is additive and
// safe, but narrowing it would break in-flight builds.
func isRemoteImportShape(path string) bool {
	if !strings.HasPrefix(path, "github.com/") {
		return false
	}
	// Require at least github.com/<org>/<repo> shape — three
	// slash-separated segments. Anything shorter is malformed.
	parts := strings.Split(path, "/")
	return len(parts) >= 3 && parts[1] != "" && parts[2] != ""
}

// isValidVersion reports whether v matches the v0.3 versioning rule:
// either a semver tag `vX.Y.Z` (mandatory `v` prefix) or a hex git SHA
// of at least 7 chars. `@latest` / `@HEAD` / bare semver fail. The
// caller surfaces a violation as HZN1704.
func isValidVersion(v string) bool {
	if v == "" {
		return false
	}
	// Semver tag.
	if strings.HasPrefix(v, "v") && len(v) >= 2 {
		rest := v[1:]
		dots := 0
		ok := true
		for _, r := range rest {
			switch {
			case r >= '0' && r <= '9':
				// digit
			case r == '.':
				dots++
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && dots == 2 {
			return true
		}
	}
	// Hex SHA prefix (>= 7 chars).
	if len(v) >= 7 {
		for _, r := range v {
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
		return true
	}
	return false
}

// resolveRemote handles import mode 4 — the lockfile + content-addressed
// cache resolution path. Behavior is gated by state.LockfileUpdate:
//   - verify mode (default): entry must exist in the lockfile, the
//     cache content sha256 must match, otherwise HZN1700/HZN1701 fires.
//   - update mode: missing entry triggers ref resolution + fetch +
//     content hashing, and the resulting LockfileEntry is returned for
//     the caller to persist.
//
// Invalid version syntax (HZN1704) fails fast in both modes.
func resolveRemote(
	imp ast.ImportDecl,
	state resolveState,
	visit func(dir string, importSpan span.Span) (ast.Package, []diag.Diagnostic, error),
) (ast.Package, []diag.Diagnostic, *LockfileEntry, error) {
	if !isValidVersion(imp.Version) {
		return ast.Package{}, []diag.Diagnostic{{
			Code:     "HZN1704",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("invalid version %q for import %q", imp.Version, imp.Path),
			Primary:  imp.Span,
			Suggest:  "use a semver tag (vX.Y.Z with the leading `v`) or a git SHA of at least 7 hex chars; `@latest` and `@HEAD` are rejected because they are not reproducible",
		}}, nil, nil
	}

	// Dedupe: a repeat import of the same remote dep from a
	// different file shouldn't emit a second HZN1700 / HZN1701 /
	// LockfileUpdate entry. The first import's verdict is the one
	// the build sees; subsequent ones short-circuit.
	if state.RemoteSeen[imp.Path] {
		// Best-effort resolution from cache if present, no
		// diagnostics either way.
		if entry, ok := state.Lockfile.LookupEntry(imp.Path); ok {
			dest := filepath.Join(cacheRoot(), cacheKey(imp.Path), entry.RefResolved)
			if dirHasHznFiles(dest) {
				dep, ds, err := visit(dest, imp.Span)
				return dep, ds, nil, err
			}
		}
		return ast.Package{}, nil, nil, nil
	}
	state.RemoteSeen[imp.Path] = true

	entry, ok := state.Lockfile.LookupEntry(imp.Path)
	if !ok {
		if !state.LockfileUpdate {
			return ast.Package{}, []diag.Diagnostic{{
				Code:     "HZN1701",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("import %q@%s is not pinned in hzn.lock", imp.Path, imp.Version),
				Primary:  imp.Span,
				Suggest:  "run `hzn get " + imp.Path + "@" + imp.Version + "` to add the entry to hzn.lock",
			}}, nil, nil
		}
		// Lockfile-update mode: resolve the version to a SHA, fetch,
		// compute content hash, build a LockfileEntry for the caller
		// to persist.
		var resolved string
		if len(imp.Version) >= 7 && !strings.HasPrefix(imp.Version, "v") {
			// Already a SHA (or SHA prefix) — short-circuit the
			// network round-trip.
			resolved = imp.Version
		} else {
			ref, refErr := resolveRef(repoURL(imp.Path), imp.Version)
			if refErr != nil || ref == "" {
				return ast.Package{}, []diag.Diagnostic{{
					Code:     "HZN1703",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("failed to resolve %s@%s to a git SHA: %v", imp.Path, imp.Version, refErr),
					Primary:  imp.Span,
					Suggest:  "verify the repository URL and the tag/branch name; for offline builds, vendor the package under ./vendor/<path>/",
				}}, nil, nil
			}
			resolved = ref
		}
		dest, fetchDiags, ferr := Fetch(imp.Path, resolved)
		if ferr != nil {
			return ast.Package{}, fetchDiags, nil, ferr
		}
		if diag.HasErrors(fetchDiags) {
			return ast.Package{}, fetchDiags, nil, nil
		}
		sum, herr := hashDirSHA256(dest)
		if herr != nil {
			return ast.Package{}, []diag.Diagnostic{{
				Code:     "HZN1703",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("hash fetched content for %s: %v", imp.Path, herr),
				Primary:  imp.Span,
			}}, nil, nil
		}
		add := &LockfileEntry{
			Path:        imp.Path,
			Version:     imp.Version,
			RefResolved: resolved,
			SHA256:      sum,
		}
		dep, ds, derr := visit(dest, imp.Span)
		return dep, ds, add, derr
	}

	// Verify mode: entry exists. Fetch (cache-hit on subsequent
	// builds, network on first build), verify sha256, then visit.
	dest, fetchDiags, ferr := Fetch(imp.Path, entry.RefResolved)
	if ferr != nil {
		return ast.Package{}, fetchDiags, nil, ferr
	}
	if diag.HasErrors(fetchDiags) {
		return ast.Package{}, fetchDiags, nil, nil
	}
	sum, herr := hashDirSHA256(dest)
	if herr != nil {
		return ast.Package{}, []diag.Diagnostic{{
			Code:     "HZN1703",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("hash cached content for %s: %v", imp.Path, herr),
			Primary:  imp.Span,
		}}, nil, nil
	}
	if sum != entry.SHA256 {
		return ast.Package{}, []diag.Diagnostic{{
			Code:     "HZN1700",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("checksum mismatch for %s@%s: lockfile=%s, cache=%s", imp.Path, entry.Version, entry.SHA256, sum),
			Primary:  imp.Span,
			Suggest:  "the cached content does not match the lockfile pin; delete the cache entry under $XDG_CACHE_HOME/horizon/modules/ and re-fetch, or run `hzn get " + imp.Path + "@" + entry.Version + "` to refresh the lockfile",
		}}, nil, nil
	}
	dep, ds, derr := visit(dest, imp.Span)
	return dep, ds, nil, derr
}

// hashDirSHA256 computes a deterministic content hash over the
// `.hzn` files inside dir (non-recursive). Hashing only language
// source files keeps the digest stable across cache repackings or
// metadata files (`.horizon-meta.json`) and matches the unit of
// content the resolver actually consumes. The hash is the sha256 of
// the sorted concatenation `<relpath>\n<size>\n<bytes>\n` per file.
func hashDirSHA256(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".hzn") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	h := sha256New()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\n%d\n", name, len(raw))
		h.Write(raw)
		h.Write([]byte{'\n'})
	}
	return sha256Hex(h), nil
}

func importNotFoundDiag(imp ast.ImportDecl, where string) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN1554",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("imported package %q not found (looked at %s)", imp.Path, where),
		Primary:  imp.Span,
		Suggest:  "check the import path spelling, or vendor the package under ./vendor/<path>/",
	}
}

// isCompilerNamespaceName mirrors types.compilerNamespace's hardcoded list so
// the resolver can detect import-alias collisions (HZN1004 extension) without
// pulling the types package as a dependency. Keep this list in sync with
// types/checker.go::compilerNamespaceWithAliases.
func isCompilerNamespaceName(name string) bool {
	switch name {
	case "bpf", "xdp", "tc", "cgroup", "lsm", "kprobe", "kretprobe", "tracepoint":
		return true
	}
	return false
}

// dirHasHznFiles reports whether dir exists, is a directory, and contains at
// least one .hzn file (non-recursive — the vendor walk only cares about the
// nominated directory).
func dirHasHznFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".hzn") {
			return true
		}
	}
	return false
}

// loadPackage parses every .hzn file directly under dir (non-recursive) and
// returns an ast.Package with stable file ordering. .hzn files inside nested
// directories are NOT included — those belong to their own packages.
//
// Files carrying `//hzn:build <expr>` constraint directives are evaluated
// against ctx; files whose constraint fails (or whose expression is itself
// malformed) are filtered out before parsing — they contribute no
// declarations and produce no parse/AST diagnostics. Malformed expressions
// do surface as a non-fatal warning so authors notice typos. The surviving
// files have their joined constraint recorded on `ast.File.BuildTag` for
// downstream reproducibility.
//
// If singlePath is non-empty, only that one file is loaded into the package
// (used when AnalyzePath is called with a file path instead of a directory).
// Single-file mode still honors build constraints — a file pointed at
// explicitly whose constraint fails is still filtered out.
func loadPackage(dir, singlePath string, ctx BuildContext) (ast.Package, []diag.Diagnostic, error) {
	var paths []string
	if singlePath != "" {
		paths = []string{singlePath}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return ast.Package{}, nil, fmt.Errorf("read package dir %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".hzn") {
				paths = append(paths, filepath.Join(dir, entry.Name()))
			}
		}
		slices.Sort(paths)
	}
	var pkg ast.Package
	var diags []diag.Diagnostic
	for _, path := range paths {
		// Normalize to a working-directory-relative path before parsing so
		// AST file spans (and every downstream artifact that carries them —
		// source maps, reports, hznmap) match the single-package
		// AnalyzePath convention. ResolveImports works in absolute-path
		// terms for resolution correctness; only the *recorded* span needs
		// to be relative.
		parsePath := relativeToCwd(path)

		// Filter by `//hzn:build` constraints BEFORE parsing — tag-
		// excluded files never produce parse errors. A read failure
		// here is rare (we already enumerated the dir) but is recovered
		// gracefully: the file gets parsed normally and any subsequent
		// I/O failure surfaces through the parser.
		raw, rerr := os.ReadFile(path)
		joinedTag := ""
		if rerr == nil {
			tags := parser.ExtractBuildTags(raw)
			include, joined, mderr := evaluateBuildTags(ctx, tags)
			if mderr != nil {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1680",
					Severity: diag.SeverityWarning,
					Message:  fmt.Sprintf("malformed //hzn:build directive in %s: %v", parsePath, mderr),
					Suggest:  "check the constraint expression (allowed dimensions: os, arch, kernel comparisons, btf)",
				})
				// Treat malformed directives as "exclude" — safer than
				// silently treating them as always-true.
				continue
			}
			if !include {
				continue
			}
			joinedTag = joined
		}

		parsed, perr := parser.ParsePath(parsePath)
		if perr != nil {
			diags = append(diags, frontEndDiagnostic(parsePath, perr))
			continue
		}
		file, ferr := ast.Build(parsed)
		if ferr != nil {
			diags = append(diags, frontEndDiagnostic(parsePath, ferr))
			continue
		}
		file.BuildTag = joinedTag
		if pkg.Name == "" {
			pkg.Name = file.Package
			pkg.Span = file.Span
		}
		pkg.Files = append(pkg.Files, *file)
	}
	// Determinism for callers that iterate.
	sort.SliceStable(pkg.Files, func(i, j int) bool {
		return string(pkg.Files[i].Span.File) < string(pkg.Files[j].Span.File)
	})
	return pkg, diags, nil
}

// evaluateBuildTags ANDs every directive against ctx. Returns
// (include, joined, err). include is false if any directive evaluates
// false; joined is the " && "-joined expression text recorded on the
// surviving AST file for traceability. err is non-nil only when one of
// the expressions is malformed (unknown identifier, etc.).
func evaluateBuildTags(ctx BuildContext, tags []string) (bool, string, error) {
	if len(tags) == 0 {
		return true, "", nil
	}
	for _, t := range tags {
		ok, err := ctx.Matches(t)
		if err != nil {
			return false, "", err
		}
		if !ok {
			return false, "", nil
		}
	}
	return true, strings.Join(tags, " && "), nil
}
