package ir

import (
	"fmt"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

// ImportGraph carries the minimal cross-package alias information FromPackages
// needs to tag each dependency's declarations with their import alias. The
// compiler-layer compiler.ImportGraph is a richer shape that also tracks
// builtin namespaces, edges-by-importer, and the full per-directory ast.Package
// map; this IR-local shape strips it down to the only thing lowering cares
// about: "for dependency package P resolved at directory D, what alias did
// the root import it as?" The compiler glue translates between the two.
type ImportGraph struct {
	// PackageAliases maps the dependency package's resolved directory path
	// (compiler.ImportGraph keying) → import alias as declared in the root
	// package's `import <alias> "<path>"`. If a package was reached via a
	// transitive path with no root-level alias, an empty alias means the
	// caller must fall back to the dependency's own Package name. Lowering
	// always uses the alias when populating Origin to keep manifest names
	// stable against future package renames.
	PackageAliases map[string]string
}

// FromPackages lowers a root package and its dependency packages into a
// single ir.Program. Each dependency's declarations are tagged with the
// import alias under which the root binds the dependency (graph.PackageAliases)
// so downstream aggregation can emit qualified manifest names (e.g.
// "events.ExecObserve"). Root-package declarations have Origin == "" and
// behave identically to single-package FromAST output.
//
// The function preserves single-package semantics when deps is empty — the
// root package's files are merged and lowered exactly as the legacy
// mergeASTFiles + FromAST path would have done.
//
// FromPackages is roadmap #20 Phase 2 Subtask 4a's orchestrator. Single-file
// callers should keep using FromAST; multi-package callers should route
// through here so origin tagging is centralized.
func FromPackages(root ast.Package, deps []ast.Package, graph ImportGraph) (Program, []diag.Diagnostic) {
	var diags []diag.Diagnostic

	rootProgram, rootDiags := lowerPackage(root, "")
	diags = append(diags, rootDiags...)

	depPrograms := make([]Program, 0, len(deps))
	depStructsByAlias := map[string]map[string]bool{}
	for _, dep := range deps {
		alias := aliasForPackage(dep, graph)
		depProg, depDiags := lowerPackage(dep, alias)
		diags = append(diags, depDiags...)
		depPrograms = append(depPrograms, depProg)
		if alias == "" {
			continue
		}
		if depStructsByAlias[alias] == nil {
			depStructsByAlias[alias] = map[string]bool{}
		}
		for _, s := range depProg.Structs {
			depStructsByAlias[alias][s.Name] = true
		}
	}

	// Rewrite cross-package qualified type references (`events.ExecEvent`) in
	// the root program to their bare form (`ExecEvent`). The merged IR keeps
	// struct identity through Origin tags; emitc and validate look up
	// declarations by their bare Name, so leaving `<alias>.<TypeName>` strings
	// in Type.Name would break downstream lookups. We rewrite only when the
	// alias is a known dependency import AND the suffix matches a struct
	// actually declared in that dep — references whose suffix is unknown stay
	// untouched so HZN1558 (already emitted by the type checker) still has a
	// recognizable name to report against. (roadmap #20 Phase 2 Subtask 6b
	// follow-up — the type checker validates qualified refs but does not
	// rewrite them.)
	if len(depStructsByAlias) > 0 {
		rewriteRootQualifiedTypes(&rootProgram, depStructsByAlias)
	}

	all := make([]Program, 0, 1+len(depPrograms))
	all = append(all, rootProgram)
	all = append(all, depPrograms...)

	merged, mergeDiags := MergeWithDiagnostics(all...)
	diags = append(diags, mergeDiags...)
	return merged, diags
}

// rewriteRootQualifiedTypes walks every Type in the root program and, when a
// Type.Name has the shape `<alias>.<Name>` where alias is a known dep import
// alias and Name matches a struct in that dep, rewrites Type.Name to the bare
// `<Name>`. Maps' Key/Val, function parameters and returns, const types, and
// local var decls inside function bodies are all covered. The depStructs map
// is keyed by alias → bare struct name → true.
func rewriteRootQualifiedTypes(program *Program, depStructs map[string]map[string]bool) {
	rewriteType := func(t *Type) {
		stripQualifiedTypeName(t, depStructs)
	}
	for i := range program.Maps {
		walkTypeTree(&program.Maps[i].Key, rewriteType)
		walkTypeTree(&program.Maps[i].Val, rewriteType)
	}
	for i := range program.Functions {
		walkTypeTree(&program.Functions[i].Return, rewriteType)
		for j := range program.Functions[i].Params {
			walkTypeTree(&program.Functions[i].Params[j].Type, rewriteType)
		}
		for j := range program.Functions[i].Body {
			for k := range program.Functions[i].Body[j].Statements {
				walkStatementTypes(&program.Functions[i].Body[j].Statements[k], rewriteType)
			}
		}
	}
	for i := range program.Constants {
		walkTypeTree(&program.Constants[i].Type, rewriteType)
	}
	for i := range program.Structs {
		for j := range program.Structs[i].Fields {
			walkTypeTree(&program.Structs[i].Fields[j].Type, rewriteType)
		}
	}
}

func stripQualifiedTypeName(t *Type, depStructs map[string]map[string]bool) {
	if t == nil || t.Name == "" {
		return
	}
	for alias, names := range depStructs {
		prefix := alias + "."
		if len(t.Name) <= len(prefix) || t.Name[:len(prefix)] != prefix {
			continue
		}
		suffix := t.Name[len(prefix):]
		if names[suffix] {
			t.Name = suffix
			return
		}
	}
}

func walkTypeTree(t *Type, visit func(*Type)) {
	if t == nil {
		return
	}
	visit(t)
	for i := range t.Args {
		walkTypeTree(&t.Args[i], visit)
	}
	if t.Elem != nil {
		walkTypeTree(t.Elem, visit)
	}
}

func walkStatementTypes(stmt *Statement, visit func(*Type)) {
	if stmt == nil {
		return
	}
	walkTypeTree(&stmt.Type, visit)
	if stmt.Init != nil {
		walkStatementTypes(stmt.Init, visit)
	}
	for i := range stmt.Then {
		walkStatementTypes(&stmt.Then[i], visit)
	}
	for i := range stmt.Else {
		walkStatementTypes(&stmt.Else[i], visit)
	}
	for i := range stmt.Body {
		walkStatementTypes(&stmt.Body[i], visit)
	}
	for i := range stmt.Cases {
		for j := range stmt.Cases[i].Body {
			walkStatementTypes(&stmt.Cases[i].Body[j], visit)
		}
	}
}

// lowerPackage flattens every File in pkg into a single ast.File (mirroring
// the compiler-layer mergeASTFiles), calls FromAST, then stamps Origin on
// every declaration that came out. We collapse first so cross-file references
// inside one package (the existing single-package multi-file path codified in
// Task 1) resolve through FromAST unchanged.
func lowerPackage(pkg ast.Package, origin string) (Program, []diag.Diagnostic) {
	var merged ast.File
	merged.Package = pkg.Name
	if len(pkg.Files) > 0 {
		merged.Span = pkg.Files[0].Span
	}
	for _, f := range pkg.Files {
		merged.Imports = append(merged.Imports, f.Imports...)
		merged.Decls = append(merged.Decls, f.Decls...)
	}
	program, diags := FromAST(merged)
	if origin == "" {
		return program, diags
	}
	for i := range program.Functions {
		program.Functions[i].Origin = origin
	}
	for i := range program.Maps {
		program.Maps[i].Origin = origin
	}
	for i := range program.Constants {
		program.Constants[i].Origin = origin
	}
	for i := range program.Structs {
		program.Structs[i].Origin = origin
	}
	for i := range program.Capabilities {
		program.Capabilities[i].Origin = origin
	}
	return program, diags
}

// aliasForPackage looks up the import alias the root package bound to dep.
// We prefer the explicit alias in graph.PackageAliases (keyed by the
// dependency's resolved-directory path, which the compiler-layer resolver
// already canonicalizes) and fall back to the dependency's own Package
// declaration when no alias is available — that fallback path is reached
// only for transitively imported packages, which Task 5 (cross-package
// aggregation) will revisit when re-export semantics land.
func aliasForPackage(dep ast.Package, graph ImportGraph) string {
	if alias, ok := graph.PackageAliases[string(dep.Span.File)]; ok && alias != "" {
		return alias
	}
	for key, alias := range graph.PackageAliases {
		// dep.Span.File is one of the source file paths; resolved
		// directory keys are dirname-y. Match if the file lives under
		// the resolved directory. We keep this loop linear because
		// dependency counts are bounded by import depth, not file count.
		if alias == "" {
			continue
		}
		if key == "" {
			continue
		}
		if isUnderDir(string(dep.Span.File), key) {
			return alias
		}
	}
	return dep.Name
}

// isUnderDir is a cheap path-prefix check that avoids pulling in filepath
// just to compare a couple of string prefixes. Returns true when path lives
// under dir (or equals it).
func isUnderDir(path, dir string) bool {
	if path == dir {
		return true
	}
	if len(path) > len(dir) && path[:len(dir)] == dir && (path[len(dir)] == '/' || path[len(dir)] == '\\') {
		return true
	}
	return false
}

// MergeWithDiagnostics concatenates programs the same way Merge does, but
// additionally surfaces diagnostics when two programs contribute symbols
// that share a qualified name (Origin + "." + Name, or bare Name when both
// Origins are empty) but differ in body shape. Same-name same-body
// duplicates fall through silently — they are the legitimate
// multi-reference-of-one-decl case that single-package multi-file builds
// already handle.
//
// The error codes are reserved in the HZN156x range:
//   - HZN1562 cross-package Function collision
//   - HZN1563 cross-package Map collision
//   - HZN1564 cross-package Struct collision
//   - HZN1565 cross-package Capability collision
//
// Same-package collisions (Origin == "" on both sides) remain the
// responsibility of types.CheckPackage / HZN1002 — IR merge is the wrong
// layer to catch them because by the time lowering runs the type checker
// has already accepted both files.
func MergeWithDiagnostics(programs ...Program) (Program, []diag.Diagnostic) {
	merged := Merge(programs...)
	var diags []diag.Diagnostic

	type fnKey struct{ qname string }
	seenFn := map[fnKey]Function{}
	for _, fn := range merged.Functions {
		key := fnKey{qname: originQualifiedName(fn.Origin, fn.Name)}
		prev, ok := seenFn[key]
		if !ok {
			seenFn[key] = fn
			continue
		}
		if fn.Origin == "" && prev.Origin == "" {
			continue
		}
		if functionsAgree(prev, fn) {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1562",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q has conflicting definitions across packages", key.qname),
			Primary:  fn.Span,
			Suggest:  "two packages declared a function with the same qualified name but different bodies; rename one or move the shared body to a single owning package",
		})
	}

	seenMap := map[string]Map{}
	for _, m := range merged.Maps {
		key := originQualifiedName(m.Origin, m.Name)
		prev, ok := seenMap[key]
		if !ok {
			seenMap[key] = m
			continue
		}
		if m.Origin == "" && prev.Origin == "" {
			continue
		}
		if mapsAgree(prev, m) {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1563",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("map %q has conflicting shapes across packages", key),
			Primary:  m.Span,
			Suggest:  "two packages declared a map with the same qualified name but different key/value/kind; rename one or move the shared map to a single owning package",
		})
	}

	seenStruct := map[string]Struct{}
	for _, s := range merged.Structs {
		key := originQualifiedName(s.Origin, s.Name)
		prev, ok := seenStruct[key]
		if !ok {
			seenStruct[key] = s
			continue
		}
		if s.Origin == "" && prev.Origin == "" {
			continue
		}
		if structsAgree(prev, s) {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1564",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("struct %q has conflicting layouts across packages", key),
			Primary:  s.Span,
			Suggest:  "two packages declared a struct with the same qualified name but different fields; rename one or move the shared definition to a single owning package",
		})
	}

	seenCap := map[string]Capability{}
	for _, c := range merged.Capabilities {
		key := originQualifiedName(c.Origin, c.Name)
		prev, ok := seenCap[key]
		if !ok {
			seenCap[key] = c
			continue
		}
		if c.Origin == "" && prev.Origin == "" {
			continue
		}
		if capabilitiesAgree(prev, c) {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1565",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("capability %q has conflicting definitions across packages", key),
			Primary:  c.Span,
			Suggest:  "two packages declared a capability with the same qualified name but different danger level or value; rename one or move the shared declaration to a single owning package",
		})
	}

	return merged, diags
}

// originQualifiedName composes the origin-qualified name used to detect
// cross-package collisions. The empty origin produces a bare name so root-
// package symbols collide only with other root-package symbols, never with
// dependency symbols of the same bare name. Distinct from build.go's
// qualifiedName, which inverts an *Expr selector chain into its source-form
// dotted name; the two helpers operate on different shapes.
func originQualifiedName(origin, name string) string {
	if origin == "" {
		return name
	}
	return origin + "." + name
}

// functionsAgree reports whether two Function values describe the same
// function — same section, same parameter shape, same return type, same
// body text. Bodies that differ in span only (re-parsed from a separate
// copy of the same source file, as a vendored package would have) are
// considered agreeing. We compare BodyText rather than Block slices because
// BodyText is the verbatim source the IR carries forward and a structural
// re-equality check on Statement trees would add a lot of code for a case
// that bites cross-package deduplication, not correctness.
func functionsAgree(a, b Function) bool {
	if a.Name != b.Name {
		return false
	}
	if a.Section != b.Section {
		return false
	}
	if !typesAgree(a.Return, b.Return) {
		return false
	}
	if len(a.Params) != len(b.Params) {
		return false
	}
	for i := range a.Params {
		if a.Params[i].Name != b.Params[i].Name {
			return false
		}
		if !typesAgree(a.Params[i].Type, b.Params[i].Type) {
			return false
		}
	}
	return a.BodyText == b.BodyText
}

func mapsAgree(a, b Map) bool {
	if a.Kind != b.Kind {
		return false
	}
	if !typesAgree(a.Key, b.Key) {
		return false
	}
	if !typesAgree(a.Val, b.Val) {
		return false
	}
	if a.MaxEntries != b.MaxEntries {
		return false
	}
	return true
}

func structsAgree(a, b Struct) bool {
	if len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i].Name != b.Fields[i].Name {
			return false
		}
		if !typesAgree(a.Fields[i].Type, b.Fields[i].Type) {
			return false
		}
	}
	return true
}

func capabilitiesAgree(a, b Capability) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Danger != b.Danger {
		return false
	}
	if a.Program != b.Program {
		return false
	}
	if a.Emits != b.Emits {
		return false
	}
	if a.Section != b.Section {
		return false
	}
	return true
}

func typesAgree(a, b Type) bool {
	if a.Name != b.Name {
		return false
	}
	if a.Len != b.Len {
		return false
	}
	if a.Ptr != b.Ptr {
		return false
	}
	if len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if !typesAgree(a.Args[i], b.Args[i]) {
			return false
		}
	}
	if (a.Elem == nil) != (b.Elem == nil) {
		return false
	}
	if a.Elem != nil && !typesAgree(*a.Elem, *b.Elem) {
		return false
	}
	return true
}
