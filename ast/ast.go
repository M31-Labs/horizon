package ast

import "m31labs.dev/horizon/compiler/span"

type File struct {
	Package string
	Imports []ImportDecl
	Decls   []Decl
	Span    span.Span
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
