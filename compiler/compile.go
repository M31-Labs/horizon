package compiler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/parser"
	htypes "m31labs.dev/horizon/types"
	"m31labs.dev/horizon/validate"
)

// relativeToCwd converts an absolute path to one relative to the working
// directory when possible. ResolveImports stamps absolute paths into each
// imported file's Span.File; this normalization keeps report goldens
// reproducible across checkouts (matches the single-package AnalyzePath
// convention where the user-supplied root is already relative).
func relativeToCwd(p string) string {
	if p == "" || !filepath.IsAbs(p) {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, p)
	if err != nil {
		return p
	}
	return rel
}

type FileResult struct {
	Path        string
	Package     string
	Diagnostics []diag.Diagnostic
}

type Result struct {
	Files       []FileResult
	Program     ir.Program
	Diagnostics []diag.Diagnostic
}

func CheckPath(root string) (*Result, error) {
	return AnalyzePath(root)
}

func AnalyzePath(root string) (*Result, error) {
	// Resolve imports before walking files. For single-package builds (only
	// builtin imports, or none at all) this is a no-op — the legacy code
	// path runs unchanged. For multi-package builds we route through the
	// cross-package wiring landed in Phase 2 Tasks 3 and 4 (types.CheckPackages
	// + ir.FromPackages). Front-end (parse / AST) diagnostics surfaced by
	// the resolver are dropped here because AnalyzePath's own loop will
	// re-encounter and report them with full source context.
	rootPkg, deps, graph, importDiags, importErr := ResolveImports(root)
	if importErr != nil {
		return nil, importErr
	}
	importDiags = filterImportDiagnostics(importDiags)
	if len(deps) > 0 {
		return analyzeMultiPackage(rootPkg, deps, graph, importDiags)
	}

	paths, err := CollectFiles(root)
	if err != nil {
		return nil, err
	}
	var result Result
	// Surface only the import-specific diagnostics (e.g. HZN1556 warning, or
	// HZN1554/HZN1555) on the legacy single-package path. Parse/AST errors
	// were filtered out above so they aren't double-counted.
	result.Diagnostics = append(result.Diagnostics, importDiags...)
	packageName := ""
	files := make([]ast.File, 0, len(paths))
	fileIndexes := make([]int, 0, len(paths))
	hadFrontEndError := false
	ctx := DetectContext()
	for _, path := range paths {
		// Apply build-tag filter on the single-package path, mirroring
		// loadPackage's behavior for the multi-package path. Tag-
		// excluded files do not contribute decls and do not produce
		// parse/AST diagnostics (roadmap #16). A read failure here is
		// soft — the parser will re-encounter and report it.
		var fileBuildTag string
		if raw, rerr := os.ReadFile(path); rerr == nil {
			tags := parser.ExtractBuildTags(raw)
			include, joined, mderr := evaluateBuildTags(ctx, tags)
			if mderr != nil {
				result.Diagnostics = append(result.Diagnostics, diag.Diagnostic{
					Code:     "HZN1680",
					Severity: diag.SeverityWarning,
					Message:  fmt.Sprintf("malformed //hzn:build directive in %s: %v", path, mderr),
					Suggest:  "check the constraint expression (allowed dimensions: os, arch, kernel comparisons, btf)",
				})
				continue
			}
			if !include {
				continue
			}
			fileBuildTag = joined
		}
		parsed, err := parser.ParsePath(path)
		if err != nil {
			hadFrontEndError = true
			d := frontEndDiagnostic(path, err)
			result.Files = append(result.Files, FileResult{
				Path:        path,
				Diagnostics: []diag.Diagnostic{d},
			})
			result.Diagnostics = append(result.Diagnostics, d)
			continue
		}
		file, err := ast.Build(parsed)
		if err != nil {
			hadFrontEndError = true
			d := frontEndDiagnostic(path, err)
			result.Files = append(result.Files, FileResult{
				Path:        path,
				Package:     parsed.Package,
				Diagnostics: []diag.Diagnostic{d},
			})
			result.Diagnostics = append(result.Diagnostics, d)
			continue
		}
		file.BuildTag = fileBuildTag
		fileIndexes = append(fileIndexes, len(result.Files))
		files = append(files, *file)
		result.Files = append(result.Files, FileResult{
			Path:    path,
			Package: file.Package,
		})
	}
	if hadFrontEndError {
		return &result, nil
	}
	typeDiags := htypes.CheckPackage(files)
	for i, file := range files {
		diags := append([]diag.Diagnostic{}, typeDiags[i]...)
		if file.Package != "" {
			if packageName == "" {
				packageName = file.Package
			} else if file.Package != packageName {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1003",
					Severity: diag.SeverityError,
					Message:  "all files in a Horizon package must use the same package declaration",
					Primary:  file.Span,
				})
			}
		}
		result.Files[fileIndexes[i]].Diagnostics = diags
		result.Diagnostics = append(result.Diagnostics, diags...)
	}
	resolveMapMaxEntries(files)
	program, lowerDiags := ir.FromAST(mergeASTFiles(files, packageName))
	result.Program = program
	result.Diagnostics = append(result.Diagnostics, lowerDiags...)
	if !diag.HasErrors(result.Diagnostics) {
		result.Diagnostics = append(result.Diagnostics, validate.Program(result.Program)...)
	}
	if !diag.HasErrors(result.Diagnostics) {
		if err := bindgen.Validate(result.Program, "bindings"); err != nil {
			if d, ok := bindgen.DiagnosticForError(err); ok {
				result.Diagnostics = append(result.Diagnostics, d)
			} else {
				return nil, err
			}
		}
	}
	return &result, nil
}

func resolveMapMaxEntries(files []ast.File) {
	consts := collectIntConsts(files)
	rewriteMapMaxEntries(files, consts)
}

// resolveMapMaxEntriesAcrossPackages is the package-aware variant used by the
// multi-package build path. It collects int-valued consts from the root
// package under their bare names, plus consts from each imported package
// under both their bare names and qualified `<alias>.<Name>` form. The map
// rewriter then resolves either form, so a root-package `@max_entries(events.MaxBufSize)`
// finds the imported const without the root needing to re-declare it.
// (roadmap #20 Phase 2 Subtask 4b.)
func resolveMapMaxEntriesAcrossPackages(rootFiles []ast.File, deps []ast.Package, aliasByDir map[string]string) {
	consts := collectIntConsts(rootFiles)
	for _, dep := range deps {
		alias := aliasByDir[string(dep.Span.File)]
		if alias == "" {
			for key, a := range aliasByDir {
				if a == "" || key == "" {
					continue
				}
				if isUnderDirPath(string(dep.Span.File), key) {
					alias = a
					break
				}
			}
		}
		if alias == "" {
			alias = dep.Name
		}
		depConsts := collectIntConsts(dep.Files)
		for name, value := range depConsts {
			// Qualified form is the one cross-package references take;
			// the bare form remains usable inside the dep's own files
			// when they are rewritten (we rewrite dep maps too so dep-
			// internal @max_entries references continue to work).
			consts[alias+"."+name] = value
			if _, exists := consts[name]; !exists {
				consts[name] = value
			}
		}
	}
	rewriteMapMaxEntries(rootFiles, consts)
	for _, dep := range deps {
		rewriteMapMaxEntries(dep.Files, consts)
	}
}

func collectIntConsts(files []ast.File) map[string]string {
	consts := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.ConstDecl:
				value, ok := d.Value.(ast.IntExpr)
				if ok {
					consts[d.Name] = value.Value
				}
			case ast.ConstGroupDecl:
				for _, constant := range d.Consts {
					value, ok := constant.Value.(ast.IntExpr)
					if ok {
						consts[constant.Name] = value.Value
					}
				}
			case ast.EnumDecl:
				for _, enumValue := range d.Values {
					value, ok := enumValue.Value.(ast.IntExpr)
					if ok {
						consts[enumValue.Name] = value.Value
					}
				}
			}
		}
	}
	return consts
}

func rewriteMapMaxEntries(files []ast.File, consts map[string]string) {
	if len(consts) == 0 {
		return
	}
	for i := range files {
		for j, decl := range files[i].Decls {
			m, ok := decl.(ast.MapDecl)
			if !ok {
				continue
			}
			if resolved, ok := consts[m.MaxEntries]; ok {
				m.MaxEntries = resolved
				rewriteMaxEntriesAttr(&m, resolved)
				files[i].Decls[j] = m
			}
		}
	}
}

// rewriteMaxEntriesAttr replaces the @max_entries attribute argument with an
// IntExpr literal when the corresponding ast.MapDecl.MaxEntries field has
// been resolved (e.g. a `@max_entries(events.MaxBufSize)` qualified-const
// reference rewritten to "4096"). Without this rewrite, the type checker's
// validateMapAttrs would reject the unresolved SelectorExpr argument with
// HZN1206. We also catch the bare-IdentExpr case for symmetry — single-
// package builds already pre-resolve MaxEntries before lowering, so this
// keeps the attribute view consistent with the resolved decl view.
func rewriteMaxEntriesAttr(m *ast.MapDecl, resolved string) {
	for i, attr := range m.Attrs {
		if attr.Name != "max_entries" || len(attr.Args) != 1 {
			continue
		}
		switch attr.Args[0].(type) {
		case ast.SelectorExpr, ast.IdentExpr:
			lit := ast.IntExpr{Value: resolved, Span: attr.Span}
			attr.Args = []ast.Expr{lit}
			m.Attrs[i] = attr
		}
	}
}

// isUnderDirPath duplicates ir.isUnderDir to avoid importing ir from here
// for one helper. Returns true when path lives under dir (or equals it).
func isUnderDirPath(path, dir string) bool {
	if path == dir {
		return true
	}
	if len(path) > len(dir) && path[:len(dir)] == dir && (path[len(dir)] == '/' || path[len(dir)] == '\\') {
		return true
	}
	return false
}

func mergeASTFiles(files []ast.File, packageName string) ast.File {
	var merged ast.File
	merged.Package = packageName
	if len(files) > 0 {
		merged.Span = files[0].Span
	}
	for _, file := range files {
		merged.Imports = append(merged.Imports, file.Imports...)
		merged.Decls = append(merged.Decls, file.Decls...)
	}
	return merged
}

// filterImportDiagnostics drops front-end (HZN0100 parse, HZN0200 AST-build)
// diagnostics emitted by ResolveImports. Those will be re-encountered with
// full source context inside AnalyzePath's own per-file parse loop; surfacing
// them from both places double-counts the same syntax error.
func filterImportDiagnostics(diags []diag.Diagnostic) []diag.Diagnostic {
	out := diags[:0]
	for _, d := range diags {
		if d.Code == "HZN0100" || d.Code == "HZN0200" {
			continue
		}
		out = append(out, d)
	}
	return out
}

func frontEndDiagnostic(path string, err error) diag.Diagnostic {
	var parseErr *parser.ParseError
	if errors.As(err, &parseErr) {
		return diag.Diagnostic{
			Code:     "HZN0100",
			Severity: diag.SeverityError,
			Message:  parseErr.Message,
			Primary:  parseErr.Span(),
			Suggest:  "fix the Horizon syntax before typechecking or C emission can continue",
		}
	}
	return diag.Diagnostic{
		Code:     "HZN0200",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("could not build Horizon AST: %v", err),
		Primary:  span.Span{File: span.FileID(path)},
	}
}

// analyzeMultiPackage is the cross-package build path: routes type-checking
// through types.CheckPackages and lowering through ir.FromPackages so each
// dependency's declarations carry their import-alias Origin into the final
// IR. The single-package path remains the default (len(deps) == 0); this
// function is reached only when ResolveImports surfaces at least one non-
// builtin dependency. (roadmap #20 Phase 2 Subtask 4b.)
func analyzeMultiPackage(rootPkg ast.Package, deps []ast.Package, graph ImportGraph, importDiags []diag.Diagnostic) (*Result, error) {
	result := &Result{Diagnostics: append([]diag.Diagnostic{}, importDiags...)}

	// Emit one FileResult per source file across the root and every dep,
	// so cmd/hzn diagnostic rendering still has a per-file home for the
	// type-checker's output. ResolveImports stamps absolute paths into
	// each file's Span.File; rewrite them relative to the working
	// directory so report goldens are reproducible across checkouts
	// (matches the single-package AnalyzePath convention).
	rootFiles := append([]ast.File{}, rootPkg.Files...)
	for _, f := range rootPkg.Files {
		result.Files = append(result.Files, FileResult{Path: relativeToCwd(string(f.Span.File)), Package: f.Package})
	}
	depFileOffsets := make([]int, len(deps))
	for di, dep := range deps {
		depFileOffsets[di] = len(result.Files)
		for _, f := range dep.Files {
			result.Files = append(result.Files, FileResult{Path: relativeToCwd(string(f.Span.File)), Package: f.Package})
		}
	}

	// Resolve cross-package map sizing BEFORE type-checking — the type
	// checker validates @max_entries values, and a still-string-form
	// "events.MaxBufSize" would fail validation. We mutate the file slices
	// in place; the type checker and lowering consume the rewritten copies.
	aliasByDir := graph.aliasByDepDir(rootPkg)
	resolveMapMaxEntriesAcrossPackages(rootFiles, deps, aliasByDir)
	rootPkg.Files = rootFiles

	typesGraph := graph.toTypesGraph(rootPkg)
	roots := append([]ast.Package{rootPkg}, deps...)
	checkResult := htypes.CheckPackages(roots, typesGraph)

	// Stable per-file diagnostic mapping. CheckPackages keys by package
	// directory (the resolved directory in graph.Packages). We look up the
	// root and each dep separately and walk per-file in declaration order.
	rootDir := graph.lookupPackageDir(rootPkg)
	if rootDiags, ok := checkResult[rootDir]; ok {
		for i := range rootPkg.Files {
			if i < len(rootDiags) {
				result.Files[i].Diagnostics = rootDiags[i]
				result.Diagnostics = append(result.Diagnostics, rootDiags[i]...)
			}
		}
	}
	for di, dep := range deps {
		depDir := graph.lookupPackageDir(dep)
		depDiags, ok := checkResult[depDir]
		if !ok {
			continue
		}
		offset := depFileOffsets[di]
		for i := range dep.Files {
			if i < len(depDiags) {
				result.Files[offset+i].Diagnostics = depDiags[i]
				result.Diagnostics = append(result.Diagnostics, depDiags[i]...)
			}
		}
	}

	// Lower through FromPackages — origin tagging happens here.
	irGraph := graph.toIRGraph(rootPkg)
	program, lowerDiags := ir.FromPackages(rootPkg, deps, irGraph)
	result.Program = program
	result.Diagnostics = append(result.Diagnostics, lowerDiags...)

	// Aggregate the per-origin partial manifests to surface
	// HZN1553/HZN1560/HZN1566/HZN1567 conflict diagnostics through the
	// compiler.Result diagnostic channel. The aggregated manifest itself is
	// discarded here — workbench/bindgen still re-derive it on demand via
	// capability.FromIR; what matters at AnalyzePath time is that the
	// cross-package collision codes surface to `hzn check`. (The IR-merge
	// layer separately emits HZN1562/1563/1564/1565 inside ir.FromPackages
	// above; ADR-0003 documents the per-layer split.) (roadmap #21 Phase 2
	// Task 6c.)
	if !diag.HasErrors(result.Diagnostics) {
		_, aggDiags := capability.FromIRWithDiagnostics(result.Program)
		result.Diagnostics = append(result.Diagnostics, aggDiags...)
	}

	if !diag.HasErrors(result.Diagnostics) {
		result.Diagnostics = append(result.Diagnostics, validate.Program(result.Program)...)
	}
	if !diag.HasErrors(result.Diagnostics) {
		if err := bindgen.Validate(result.Program, "bindings"); err != nil {
			if d, ok := bindgen.DiagnosticForError(err); ok {
				result.Diagnostics = append(result.Diagnostics, d)
			} else {
				return nil, err
			}
		}
	}
	return result, nil
}

// toTypesGraph projects the compiler's ImportGraph into the types-layer
// shape. The two graphs hold the same information; the types package keeps
// its own type to avoid a compiler → types → compiler import cycle.
func (g ImportGraph) toTypesGraph(root ast.Package) htypes.ImportGraph {
	out := htypes.ImportGraph{
		Edges:          g.Edges,
		Packages:       g.Packages,
		BuiltinAliases: g.BuiltinAliases,
	}
	return out
}

// toIRGraph projects the compiler's ImportGraph into the ir-layer shape.
// Only the per-directory → alias map matters for IR lowering; ir does not
// look at edges-by-importer or builtin aliases (those are types-layer
// concerns).
func (g ImportGraph) toIRGraph(root ast.Package) ir.ImportGraph {
	aliases := map[string]string{}
	rootDir := g.lookupPackageDir(root)
	if rootDir == "" {
		return ir.ImportGraph{PackageAliases: aliases}
	}
	for alias, resolvedPath := range g.Edges[rootDir] {
		if g.BuiltinAliases[alias] {
			continue
		}
		aliases[resolvedPath] = alias
	}
	return ir.ImportGraph{PackageAliases: aliases}
}

// aliasByDepDir returns alias-by-resolved-dir for the root package's
// non-builtin imports. Used by resolveMapMaxEntriesAcrossPackages to find
// each dep's binding alias without re-walking the graph.
func (g ImportGraph) aliasByDepDir(root ast.Package) map[string]string {
	out := map[string]string{}
	rootDir := g.lookupPackageDir(root)
	if rootDir == "" {
		return out
	}
	for alias, resolvedPath := range g.Edges[rootDir] {
		if g.BuiltinAliases[alias] {
			continue
		}
		out[resolvedPath] = alias
	}
	return out
}

// lookupPackageDir reverse-walks graph.Packages to find pkg's resolved
// directory key. Returns "" if pkg is not in the graph (which can happen
// for an ast.Package built outside the resolver — only test fixtures
// trigger that branch).
func (g ImportGraph) lookupPackageDir(pkg ast.Package) string {
	for dir, candidate := range g.Packages {
		if candidate.Name == pkg.Name && len(candidate.Files) == len(pkg.Files) {
			// Match on file-list identity to disambiguate two packages
			// with the same Name resolved at different directories.
			match := true
			for i := range candidate.Files {
				if candidate.Files[i].Span.File != pkg.Files[i].Span.File {
					match = false
					break
				}
			}
			if match {
				return dir
			}
		}
	}
	return ""
}
