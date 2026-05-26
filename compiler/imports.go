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
	graph.Edges = map[string]map[string]string{}
	graph.Packages = map[string]ast.Package{}
	graph.BuiltinAliases = map[string]bool{}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return ast.Package{}, nil, graph, nil, fmt.Errorf("resolve absolute path for %s: %w", rootDir, err)
	}

	// Visited state for DFS / cycle detection. Keys are canonical absolute
	// directory paths. addedToDeps tracks whether a non-root package has been
	// emitted into the deps slice, so transitive packages reached via shared
	// branches still surface exactly once.
	onStack := map[string]bool{}
	addedToDeps := map[string]bool{}

	var visit func(dir string, importSpan span.Span) (ast.Package, []diag.Diagnostic, error)
	visit = func(dir string, importSpan span.Span) (ast.Package, []diag.Diagnostic, error) {
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

		pkg, ds, err := loadPackage(dir)
		if err != nil {
			return ast.Package{}, ds, err
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
				edge, depPkg, depDiags, derr := resolveOne(dir, absRoot, imp, visit)
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

	root, rootDiags, rerr := visit(absRoot, span.Span{File: span.FileID(absRoot)})
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
func loadPackage(dir string) (ast.Package, []diag.Diagnostic, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ast.Package{}, nil, fmt.Errorf("read package dir %s: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".hzn") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	slices.Sort(paths)
	var pkg ast.Package
	var diags []diag.Diagnostic
	for _, path := range paths {
		parsed, perr := parser.ParsePath(path)
		if perr != nil {
			diags = append(diags, frontEndDiagnostic(path, perr))
			continue
		}
		file, ferr := ast.Build(parsed)
		if ferr != nil {
			diags = append(diags, frontEndDiagnostic(path, ferr))
			continue
		}
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
