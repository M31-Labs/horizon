package ast

import "m31labs.dev/horizon/compiler/span"

type TypeDecl struct {
	Name   string
	Fields []Field
	Span   span.Span
}

func (TypeDecl) declNode() {}
func (d TypeDecl) GetSpan() span.Span {
	return d.Span
}

type FuncDecl struct {
	Name     string
	Attrs    []Attr
	Params   []Param
	Return   TypeRef
	Body     []Stmt
	BodyText string
	Span     span.Span
}

func (FuncDecl) declNode() {}
func (d FuncDecl) GetSpan() span.Span {
	return d.Span
}

type MapKind string

const (
	MapKindRingbuf MapKind = "ringbuf"
	MapKindHash    MapKind = "hash"
	MapKindArray   MapKind = "array"
)

type MapDecl struct {
	Name string
	Kind MapKind
	Key  TypeRef
	Val  TypeRef
	Span span.Span
}

func (MapDecl) declNode() {}
func (d MapDecl) GetSpan() span.Span {
	return d.Span
}

type ConstDecl struct {
	Name  string
	Value Expr
	Span  span.Span
}

func (ConstDecl) declNode() {}
func (d ConstDecl) GetSpan() span.Span {
	return d.Span
}
