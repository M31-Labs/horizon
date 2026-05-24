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
	MapKindRingbuf     MapKind = "ringbuf"
	MapKindHash        MapKind = "hash"
	MapKindArray       MapKind = "array"
	MapKindPerCPUHash  MapKind = "percpu_hash"
	MapKindPerCPUArray MapKind = "percpu_array"
	MapKindLRUHash     MapKind = "lru_hash"
	MapKindLRUPerCPU   MapKind = "lru_percpu_hash"
)

func (k MapKind) IsLookup() bool {
	return k.IsHashLike() || k.IsArrayLike()
}

func (k MapKind) IsHashLike() bool {
	return k == MapKindHash || k == MapKindPerCPUHash || k == MapKindLRUHash || k == MapKindLRUPerCPU
}

func (k MapKind) IsArrayLike() bool {
	return k == MapKindArray || k == MapKindPerCPUArray
}

type MapDecl struct {
	Name       string
	Attrs      []Attr
	Kind       MapKind
	Key        TypeRef
	Val        TypeRef
	MaxEntries string
	Span       span.Span
}

func (MapDecl) declNode() {}
func (d MapDecl) GetSpan() span.Span {
	return d.Span
}

type ConstDecl struct {
	Name  string
	Type  TypeRef
	Value Expr
	Span  span.Span
}

func (ConstDecl) declNode() {}
func (d ConstDecl) GetSpan() span.Span {
	return d.Span
}
