package ast

import "m31labs.dev/horizon/compiler/span"

type File struct {
	Package string
	Imports []ImportDecl
	Decls   []Decl
	Span    span.Span
	// BuildTag is the raw `//hzn:build <expr>` constraint expression
	// recorded by the compiler when the file passed the active
	// BuildContext filter. Empty when the file declared no
	// `//hzn:build` directive. When multiple directives are present
	// they are joined with " && " in source order, mirroring the
	// caller-side AND semantics. Informational only — the filter
	// decision already happened by the time the file lands in
	// ast.Package.
	BuildTag string
}

type Decl interface {
	declNode()
	GetSpan() span.Span
}

type ImportDecl struct {
	Alias string
	Path  string
	Span  span.Span
}

// Package is an aggregate of all .hzn files that share a `package <name>`
// declaration under a single resolved directory. It is the unit consumed by
// cross-package type-checking and IR lowering (introduced for v0.2 #20).
//
// Files lists each source file that contributes declarations to this package,
// in stable, sorted order. ImportEdges captures the per-package import set —
// each entry is one `import alias "path"` line, with resolution metadata
// populated by compiler.ResolveImports.
type Package struct {
	Name        string
	Files       []File
	ImportEdges []ImportEdge
	Span        span.Span
}

// ImportEdge is a resolved import: the local alias under which a foreign
// package is bound inside this package's files, plus the resolution outcome.
// ResolvedPath is the directory the foreign package was found in (for
// filesystem-resolved imports) or the canonical builtin path string (for
// compiler-builtin namespaces like `m31labs.dev/horizon/runtime/kernel`).
// Builtin is true exactly when the import resolves to a compiler-builtin
// namespace and contributed no on-disk package to walk.
type ImportEdge struct {
	Alias        string
	ResolvedPath string
	Builtin      bool
	Span         span.Span
}

type Attr struct {
	Name string
	Args []Expr
	Span span.Span
}

type Param struct {
	Name string
	Type TypeRef
	Span span.Span
}

type Field struct {
	Name string
	Type TypeRef
	Span span.Span
}
