package types

import (
	"fmt"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

// reExportKind classifies the source-side declaration kind of a
// re-exported symbol. Only types and helper functions are
// re-exportable in v0.3 (Q-15.2). Maps, capabilities, and constants
// are out of scope.
type reExportKind int

const (
	reExportKindUnknown reExportKind = iota
	reExportKindType
	reExportKindFunc
)

// reExportTarget records the originating decl behind a successful
// `export <alias>.<Name>` declaration. OriginPackage is the source
// package's own name (i.e. the value the IR layer should stamp on the
// re-exported decl's Origin field — preserving the *original* origin
// even when a downstream consumer reaches the symbol via a re-export
// chain, per the manifest-origin-preservation contract in
// decisions/0007 §"Manifest origin preservation").
type reExportTarget struct {
	Kind          reExportKind
	OriginPackage string
	OriginAlias   string // the alias the re-exporting package used (e.g. "events" when mw says `import events ...; export events.X`)
	StructDecl    ast.TypeDecl
	FuncDecl      ast.FuncDecl
}

// reExportSurface is the per-re-exporting-package summary of which
// symbols become reachable via this package via re-export. Indexed by
// symbol name → target. Used by buildImportedDecls to augment an
// imported package's known-type / func surface with its re-exports so
// downstream consumers see the same set whether the symbol was
// declared locally or pulled in via `export`.
type reExportSurface map[string]reExportTarget

// resolvePackageReExports walks every ExportDecl in a package's files
// and resolves each against the package's import graph. It returns
// the surface (valid re-exports keyed by name) plus per-file
// diagnostics. The walk implements §Step 4.5:
//
//   - HZN1690 if the target name is not declared in the named import
//     (covers missing targets, same-package exports without an alias
//     match, and second-hop re-exports — per O-3 / one-hop-only).
//   - HZN1691 if the target is present but not exported per the v0.3
//     capitalization rule. Composes with #17 privacy.
//   - HZN1692 if the re-exported name collides with a local
//     declaration in the re-exporting package.
//
// Per Q-15.2, only types and helper functions are re-exportable in
// v0.3. Maps, capabilities, and constants in the source package are
// invisible to the re-export resolver — referencing them surfaces
// HZN1690 because the re-exporter's allowed shape is "types and
// helpers only."
func resolvePackageReExports(
	pkgDir string,
	pkg ast.Package,
	graph ImportGraph,
	localDeclNames map[string]bool,
) (reExportSurface, [][]diag.Diagnostic) {
	perFileDiags := make([][]diag.Diagnostic, len(pkg.Files))
	if len(pkg.Files) == 0 {
		return nil, perFileDiags
	}

	// Collect every export-decl with its file index so diagnostics
	// land in the originating file's slice.
	type pendingExport struct {
		fileIdx int
		decl    ast.ExportDecl
	}
	var pending []pendingExport
	for i, f := range pkg.Files {
		for _, ed := range f.Exports {
			pending = append(pending, pendingExport{fileIdx: i, decl: ed})
		}
	}
	if len(pending) == 0 {
		return nil, perFileDiags
	}

	edges := graph.Edges[pkgDir]
	surface := reExportSurface{}

	for _, pe := range pending {
		ed := pe.decl

		// 1. Resolve the named alias against the package's import
		//    edges first (O-3). A bare same-package alias falls
		//    through here because the package never imports itself;
		//    the lookup returns "" and we emit HZN1690 — same-package
		//    `export X` is rejected because `export` is exclusively
		//    for re-exporting from imports.
		depDir, ok := edges[ed.Alias]
		if !ok {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1690",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-exported symbol %q not found in package %q", ed.Name, ed.Alias),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("ensure `import %s \"<path>\"` declares the source package and that %s.%s is a top-level type or helper there", ed.Alias, ed.Alias, ed.Name),
			})
			continue
		}
		depPkg, ok := graph.Packages[depDir]
		if !ok {
			// Builtin namespace or otherwise unresolved. Builtins
			// have no re-exportable surface.
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1690",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-exported symbol %q not found in package %q", ed.Name, ed.Alias),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("compiler-builtin namespaces such as bpf, xdp, tc have no re-exportable surface; re-export from a user package instead"),
			})
			continue
		}

		// 4. Look up the target name in the source package's
		//    *declared* (NOT re-exported) decls. Per the one-hop-only
		//    rule, we walk only direct declarations — the source
		//    package's own `export` decls are not visible to a
		//    second-hop re-exporter (test TestReExportIsOneHopOnly).
		kind, structDecl, funcDecl, found := lookupDirectDecl(depPkg, ed.Name)
		if !found {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1690",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-exported symbol %q not found in package %q", ed.Name, ed.Alias),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("re-exports flow one hop only — if %s.%s itself comes from another re-export, import the original package directly", ed.Alias, ed.Name),
			})
			continue
		}

		// 5. Privacy gate (HZN1691) — composes with #17. Lowercase
		//    targets cannot cross a package boundary even via
		//    re-export.
		if !isExported(ed.Name) {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1691",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("symbol %q is not exported from package %q — capitalize the first letter to export it before re-exporting", ed.Name, ed.Alias),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("rename to %s in package %q and update the export to `export %s.%s`", suggestExportedRename(ed.Name), ed.Alias, ed.Alias, suggestExportedRename(ed.Name)),
			})
			continue
		}

		// 6. Local-decl shadow check (HZN1692). Done AFTER the
		//    structural checks above so a same-package or
		//    missing-target export reports the more specific HZN1690
		//    rather than collapsing into shadow noise.
		if localDeclNames[ed.Name] {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1692",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-export of %q shadows a local declaration in package %q", ed.Name, pkg.Name),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("rename either the local %q or remove the `export %s.%s` line", ed.Name, ed.Alias, ed.Name),
			})
			continue
		}

		// 7. Duplicate re-export check (also HZN1692). Two re-exports
		//    under the same name are ambiguous regardless of source.
		if _, dup := surface[ed.Name]; dup {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1692",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-export of %q duplicates an earlier `export` in package %q", ed.Name, pkg.Name),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("remove one of the `export %s.%s` declarations", ed.Alias, ed.Name),
			})
			continue
		}

		// 8. Valid re-export. Record the surface entry.
		surface[ed.Name] = reExportTarget{
			Kind:          kind,
			OriginPackage: depPkg.Name,
			OriginAlias:   ed.Alias,
			StructDecl:    structDecl,
			FuncDecl:      funcDecl,
		}
	}

	return surface, perFileDiags
}

// lookupDirectDecl scans the direct (non-re-exported) declarations of
// pkg for a top-level decl named exactly target. Returns the kind +
// the matching ast.TypeDecl OR ast.FuncDecl. Capability/map/const
// declarations are out of scope for v0.3 re-exports — they return
// found=false so HZN1690 surfaces.
func lookupDirectDecl(pkg ast.Package, target string) (reExportKind, ast.TypeDecl, ast.FuncDecl, bool) {
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.TypeDecl:
				if d.Name == target && !d.IsAlias() {
					return reExportKindType, d, ast.FuncDecl{}, true
				}
			case ast.TypeGroupDecl:
				for _, t := range d.Types {
					if t.Name == target && !t.IsAlias() {
						return reExportKindType, t, ast.FuncDecl{}, true
					}
				}
			case ast.FuncDecl:
				if d.Name == target {
					return reExportKindFunc, ast.TypeDecl{}, d, true
				}
			}
		}
	}
	return reExportKindUnknown, ast.TypeDecl{}, ast.FuncDecl{}, false
}

// packageLocalDeclNames extracts the set of top-level decl names a
// package declares directly (NOT including its own re-exports). Used
// by resolvePackageReExports to detect HZN1692 shadow collisions.
func packageLocalDeclNames(pkg ast.Package) map[string]bool {
	out := map[string]bool{}
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.TypeDecl:
				if d.Name != "" {
					out[d.Name] = true
				}
			case ast.TypeGroupDecl:
				for _, t := range d.Types {
					if t.Name != "" {
						out[t.Name] = true
					}
				}
			case ast.FuncDecl:
				if d.Name != "" {
					out[d.Name] = true
				}
			case ast.MapDecl:
				if d.Name != "" {
					out[d.Name] = true
				}
			case ast.ConstDecl:
				if d.Name != "" {
					out[d.Name] = true
				}
			case ast.ConstGroupDecl:
				for _, c := range d.Consts {
					if c.Name != "" {
						out[c.Name] = true
					}
				}
			case ast.EnumDecl:
				for _, v := range d.Values {
					if v.Name != "" {
						out[v.Name] = true
					}
				}
			case ast.CapabilityDecl:
				if d.Name != "" {
					out[d.Name] = true
				}
			}
		}
	}
	return out
}

// computeAllReExports resolves re-exports for every package in the
// graph. The returned per-pkg surface map is used to augment imported
// package decl indexes (so a downstream consumer sees the
// re-exporter's effective surface), and the per-pkg diagnostics map
// flows back through CheckPackages so each package's diagnostics
// land in its own per-file slice.
func computeAllReExports(graph ImportGraph) (
	surfaces map[string]reExportSurface,
	diagsByDir map[string][][]diag.Diagnostic,
) {
	surfaces = map[string]reExportSurface{}
	diagsByDir = map[string][][]diag.Diagnostic{}
	for dir, pkg := range graph.Packages {
		locals := packageLocalDeclNames(pkg)
		surf, perFile := resolvePackageReExports(dir, pkg, graph, locals)
		if len(surf) > 0 {
			surfaces[dir] = surf
		}
		diagsByDir[dir] = perFile
	}
	return surfaces, diagsByDir
}
