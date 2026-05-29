package ast

import "m31labs.dev/horizon/compiler/span"

type TypeDecl struct {
	Name   string
	Alias  TypeRef
	Fields []Field
	Span   span.Span
}

func (TypeDecl) declNode() {}
func (d TypeDecl) GetSpan() span.Span {
	return d.Span
}

func (d TypeDecl) IsAlias() bool {
	return !d.Alias.IsZero()
}

type TypeGroupDecl struct {
	Types []TypeDecl
	Span  span.Span
}

func (TypeGroupDecl) declNode() {}
func (d TypeGroupDecl) GetSpan() span.Span {
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
	// MapKindStructOps is a struct_ops map: Val names the kernel ops struct
	// (e.g. tcp_congestion_ops). It is not a lookup map — IsLookup/IsHashLike/
	// IsArrayLike all return false for it by construction (v0.4 Track A A2,
	// decision 0010).
	MapKindStructOps MapKind = "struct_ops"
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
	Name               string
	Attrs              []Attr
	Kind               MapKind
	Key                TypeRef
	Val                TypeRef
	MaxEntries         string
	SteadyStateEntries string // empty if not declared
	AccessFreq         string // empty if not declared; values: "low", "medium", "high"
	Span               span.Span
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

type ConstGroupDecl struct {
	Consts []ConstDecl
	Span   span.Span
}

func (ConstGroupDecl) declNode() {}
func (d ConstGroupDecl) GetSpan() span.Span {
	return d.Span
}

type EnumDecl struct {
	Name   string
	Type   TypeRef
	Values []EnumValue
	Span   span.Span
}

func (EnumDecl) declNode() {}
func (d EnumDecl) GetSpan() span.Span {
	return d.Span
}

type EnumValue struct {
	Name  string
	Value Expr
	Span  span.Span
}

func (v EnumValue) GetSpan() span.Span {
	return v.Span
}

type CapabilityDecl struct {
	Name   string
	Value  string
	Danger string
	Span   span.Span
}

func (CapabilityDecl) declNode() {}
func (d CapabilityDecl) GetSpan() span.Span {
	return d.Span
}
