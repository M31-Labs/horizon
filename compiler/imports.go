package compiler

import (
	"fmt"
	"os"
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
// path (with HZN1556 warning), or (d) a vendored package directory found by
// walking parent dirs for `vendor/<full-path>/`. Unresolved imports produce
// HZN1554; import cycles produce HZN1555.
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
	graph.Edges = map[string]map[string]string{}
	graph.Packages = map[string]ast.Package{}
	graph.BuiltinAliases = map[string]bool{}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return ast.Package{}, nil, graph, nil, fmt.Errorf("resolve absolute path for %s: %w", rootDir, err)
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
				edge, depPkg, depDiags, derr := resolveOne(dir, absRoot, imp, func(d string, s span.Span) (ast.Package, []diag.Diagnostic, error) {
					return visit(d, s, "")
				})
				ds = append(ds, depDiags...)
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
		return root, deps, graph, diags, rerr
	}
	return root, deps, graph, diags, nil
}

// resolveOne maps a single ast.ImportDecl to a resolved package directory (or
// a builtin stub). The resolution order mirrors the plan's §Import shape:
//  1. exact match against builtinImportPaths
//  2. relative path (./, ../)
//  3. absolute path (warn HZN1556)
//  4. vendor walk for URL-shaped paths
//  5. not-found → HZN1554
func resolveOne(
	currentDir, buildRoot string,
	imp ast.ImportDecl,
	visit func(dir string, importSpan span.Span) (ast.Package, []diag.Diagnostic, error),
) (ast.ImportEdge, ast.Package, []diag.Diagnostic, error) {
	edge := ast.ImportEdge{Alias: imp.Alias, Span: imp.Span}

	// 1. Builtin.
	if _, ok := builtinImportPaths[imp.Path]; ok {
		edge.ResolvedPath = imp.Path
		edge.Builtin = true
		return edge, ast.Package{}, nil, nil
	}

	// 2. Relative.
	if strings.HasPrefix(imp.Path, "./") || strings.HasPrefix(imp.Path, "../") {
		abs, err := filepath.Abs(filepath.Join(currentDir, imp.Path))
		if err != nil {
			return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, err.Error())}, nil
		}
		if !dirHasHznFiles(abs) {
			return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, abs)}, nil
		}
		edge.ResolvedPath = abs
		dep, ds, err := visit(abs, imp.Span)
		return edge, dep, ds, err
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
			return edge, ast.Package{}, []diag.Diagnostic{warn, importNotFoundDiag(imp, imp.Path)}, nil
		}
		edge.ResolvedPath = imp.Path
		dep, ds, err := visit(imp.Path, imp.Span)
		return edge, dep, append([]diag.Diagnostic{warn}, ds...), err
	}

	// 4. URL-shaped vendored path. Walk parent directories looking for the
	// nearest `vendor/<full-path>/` rooted at or above currentDir; never walk
	// above buildRoot.
	dir := currentDir
	for {
		candidate := filepath.Join(dir, "vendor", filepath.FromSlash(imp.Path))
		if dirHasHznFiles(candidate) {
			edge.ResolvedPath = candidate
			dep, ds, err := visit(candidate, imp.Span)
			return edge, dep, ds, err
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

	// 5. Not found.
	return edge, ast.Package{}, []diag.Diagnostic{importNotFoundDiag(imp, imp.Path)}, nil
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
