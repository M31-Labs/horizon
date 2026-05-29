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
// diagnostics. It resolves:
//
//   - HZN1690 if the target name is not declared in the named import
//     and (in pass 2) is not present in the source package's own
//     pass-1 re-export surface either (covers missing targets,
//     same-package exports without an alias match, third-hop+, and
//     cyclic re-exports).
//   - HZN1691 if the target is present but not exported per the v0.3
//     capitalization rule. Composes with #17 privacy.
//   - HZN1692 if the re-exported name collides with a local
//     declaration in the re-exporting package.
//
// Per Q-15.2, only types and helper functions are re-exportable.
// Maps, capabilities, and constants in the source package are
// invisible to the re-export resolver — referencing them surfaces
// HZN1690 because the re-exporter's allowed shape is "types and
// helpers only."
//
// v0.4 (C4) two-pass second-hop resolution (Q-C4.1): when
// pass1Surfaces is nil, this performs PASS 1 — direct-only
// resolution (the v0.3 behavior). When pass1Surfaces is non-nil, this
// performs PASS 2: a target that is not a direct declaration of the
// named source package is rescued by consulting that source package's
// pass-1 surface, recording the entry against the *original*
// OriginPackage/decl so origin is preserved through both hops. There
// is no pass 3, so the third hop and cyclic chains stay rejected
// (HZN1690) with no risk of an infinite loop.
func resolvePackageReExports(
	pkgDir string,
	pkg ast.Package,
	graph ImportGraph,
	localDeclNames map[string]bool,
	pass1Surfaces map[string]reExportSurface,
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

		// 3b. v0.4 (C4, stretch) wildcard re-export. `export <alias>.*`
		//     lifts the source package's *full exportable surface* —
		//     every capitalized direct type/func plus (in pass 2) the
		//     source's own pass-1 re-exports. Origin is preserved per
		//     entry: a direct decl's origin is the source package, a
		//     re-exported entry keeps the original defining package.
		//     An empty surface emits HZN1693. Wildcard expansion is
		//     single-level: it does NOT recurse into the source's own
		//     wildcard re-exports.
		if ed.Name == "*" {
			expanded := wildcardSurface(depPkg, ed.Alias, depDir, pass1Surfaces)
			if len(expanded) == 0 {
				perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
					Code:     "HZN1693",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("wildcard re-export %q matched no exportable symbols", ed.Alias+".*"),
					Primary:  ed.Span,
					Suggest:  fmt.Sprintf("package %q exports no top-level types or helpers — re-export named symbols, or capitalize a declaration to export it", ed.Alias),
				})
				continue
			}
			for name, target := range expanded {
				// Local-decl shadow (HZN1692) and duplicate (HZN1692)
				// checks apply per expanded name, mirroring the named
				// re-export path below.
				if localDeclNames[name] {
					perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
						Code:     "HZN1692",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("wildcard re-export of %q shadows a local declaration in package %q", name, pkg.Name),
						Primary:  ed.Span,
						Suggest:  fmt.Sprintf("rename the local %q or re-export named symbols instead of `export %s.*`", name, ed.Alias),
					})
					continue
				}
				if _, dup := surface[name]; dup {
					perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
						Code:     "HZN1692",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("wildcard re-export of %q duplicates an earlier `export` in package %q", name, pkg.Name),
						Primary:  ed.Span,
						Suggest:  fmt.Sprintf("remove the duplicate `export %s.%s` or the conflicting `export %s.*`", ed.Alias, name, ed.Alias),
					})
					continue
				}
				surface[name] = target
			}
			continue
		}

		// 4. Look up the target name in the source package's
		//    *declared* (direct) decls.
		kind, structDecl, funcDecl, found := lookupDirectDecl(depPkg, ed.Name)
		// originPackage/originAlias default to the immediate source;
		// a second-hop rescue overwrites them with the *original*
		// origin so the manifest preserves it through both hops.
		originPackage := depPkg.Name
		originAlias := ed.Alias

		// 4b. v0.4 (C4) second-hop rescue. In PASS 2, if the target
		//     is not a direct decl of the named source package,
		//     consult that source package's *pass-1* re-export
		//     surface. A match there means the target is itself a
		//     (one-hop) re-export in the source package — so this
		//     `export` is the SECOND hop, which now resolves. Origin
		//     is carried from the pass-1 entry so it stays the
		//     ORIGINAL defining package across both hops. Because
		//     pass1Surfaces only ever holds direct-only (one-hop)
		//     entries, this rescue is bounded to exactly one extra
		//     hop — no recursion, no pass 3, so third-hop and cyclic
		//     chains fall through to the HZN1690 below.
		if !found && pass1Surfaces != nil {
			if srcSurface, ok := pass1Surfaces[depDir]; ok {
				if t, ok := srcSurface[ed.Name]; ok {
					kind = t.Kind
					structDecl = t.StructDecl
					funcDecl = t.FuncDecl
					originPackage = t.OriginPackage
					found = true
				}
			}
		}

		if !found {
			perFileDiags[pe.fileIdx] = append(perFileDiags[pe.fileIdx], diag.Diagnostic{
				Code:     "HZN1690",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("re-exported symbol %q not found in package %q", ed.Name, ed.Alias),
				Primary:  ed.Span,
				Suggest:  fmt.Sprintf("re-exports flow at most two hops — if %s.%s is reached through a longer re-export chain, import the original package directly", ed.Alias, ed.Name),
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

		// 8. Valid re-export. Record the surface entry, preserving the
		//    original origin (which a second-hop rescue may have
		//    rewritten to the original defining package).
		surface[ed.Name] = reExportTarget{
			Kind:          kind,
			OriginPackage: originPackage,
			OriginAlias:   originAlias,
			StructDecl:    structDecl,
			FuncDecl:      funcDecl,
		}
	}

	return surface, perFileDiags
}

// wildcardSurface enumerates the full exportable surface of source
// package depPkg for an `export <alias>.*` re-export (v0.4 C4, Q-C4.3).
// It includes every capitalized direct type and helper func, plus
// (when pass1Surfaces is non-nil) the source package's own pass-1
// re-export surface — so a wildcard composes with the second hop while
// preserving each entry's original origin. Lowercase (unexported)
// declarations are excluded per the capitalization privacy rule. The
// expansion is single-level: it does NOT pull the source's own
// wildcard re-exports recursively. Returns a name → target map keyed
// by the bare symbol name (the same shape recorded in reExportSurface).
func wildcardSurface(
	depPkg ast.Package,
	alias string,
	depDir string,
	pass1Surfaces map[string]reExportSurface,
) reExportSurface {
	out := reExportSurface{}
	// Direct exported decls of the source package.
	for _, file := range depPkg.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.TypeDecl:
				if d.Name != "" && !d.IsAlias() && isExported(d.Name) {
					out[d.Name] = reExportTarget{
						Kind:          reExportKindType,
						OriginPackage: depPkg.Name,
						OriginAlias:   alias,
						StructDecl:    d,
					}
				}
			case ast.TypeGroupDecl:
				for _, t := range d.Types {
					if t.Name != "" && !t.IsAlias() && isExported(t.Name) {
						out[t.Name] = reExportTarget{
							Kind:          reExportKindType,
							OriginPackage: depPkg.Name,
							OriginAlias:   alias,
							StructDecl:    t,
						}
					}
				}
			case ast.FuncDecl:
				if d.Name != "" && isExported(d.Name) {
					out[d.Name] = reExportTarget{
						Kind:          reExportKindFunc,
						OriginPackage: depPkg.Name,
						OriginAlias:   alias,
						FuncDecl:      d,
					}
				}
			}
		}
	}
	// Second-hop: the source package's own pass-1 re-exports also
	// belong to its exportable surface. Preserve the original origin
	// from the pass-1 entry; rebind the alias to this re-exporter.
	if pass1Surfaces != nil {
		if srcSurface, ok := pass1Surfaces[depDir]; ok {
			for name, t := range srcSurface {
				if _, exists := out[name]; exists {
					continue
				}
				t.OriginAlias = alias
				out[name] = t
			}
		}
	}
	return out
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
// v0.4 (C4): runs a two-pass walk so a re-export can flow a second hop
// (Q-C4.1). Pass 1 resolves every package's *direct-only* re-export
// surface (the v0.3 behavior; pass1Surfaces == nil). Pass 2 re-resolves
// each package, this time letting a non-direct target be rescued from
// the named source package's pass-1 surface — recording the entry
// against the *original* OriginPackage so origin is preserved through
// both hops. The pass-2 surfaces and diagnostics are the final result:
// they are a strict superset of pass 1 (every pass-1 entry re-resolves
// identically; the only additions are second-hop rescues), so a single
// extra pass is sufficient and there is no pass 3 — third-hop and
// cyclic chains stay rejected (HZN1690) with no loop.
func computeAllReExports(graph ImportGraph) (
	surfaces map[string]reExportSurface,
	diagsByDir map[string][][]diag.Diagnostic,
) {
	// Pass 1: direct-only surfaces. Diagnostics are discarded here —
	// the pass-2 walk reproduces every direct resolution and is the
	// authoritative diagnostic source.
	pass1 := map[string]reExportSurface{}
	for dir, pkg := range graph.Packages {
		locals := packageLocalDeclNames(pkg)
		surf, _ := resolvePackageReExports(dir, pkg, graph, locals, nil)
		if len(surf) > 0 {
			pass1[dir] = surf
		}
	}

	// Pass 2: consult pass-1 surfaces to rescue second-hop targets.
	surfaces = map[string]reExportSurface{}
	diagsByDir = map[string][][]diag.Diagnostic{}
	for dir, pkg := range graph.Packages {
		locals := packageLocalDeclNames(pkg)
		surf, perFile := resolvePackageReExports(dir, pkg, graph, locals, pass1)
		if len(surf) > 0 {
			surfaces[dir] = surf
		}
		diagsByDir[dir] = perFile
	}
	return surfaces, diagsByDir
}
