package ir

import "m31labs.dev/horizon/compiler/span"

type Function struct {
	Name     string
	Section  Section
	Params   []Param
	Return   Type
	Body     []Block
	BodyText string
	Span     span.Span
	// Origin records the import alias of the dependency package this
	// function was lowered from, when the program is the result of a
	// multi-package build (roadmap #20 Phase 2 Subtask 4a). Functions
	// from the root package have Origin == "". Capability aggregation
	// (Task 5) consumes Origin to emit qualified manifest names.
	Origin string `json:",omitempty"`
}

type Param struct {
	Name     string
	Type     Type
	Resource bool
}

type Block struct {
	Statements []Statement
}

type Statement struct {
	Kind   string
	Name   string
	Op     string
	Type   Type
	Target *Expr
	Value  *Expr
	Expr   *Expr
	Init   *Statement
	Cond   *Expr
	Post   *Statement
	Then   []Statement
	Else   []Statement
	Body   []Statement
	Cases  []SwitchCase
	Span   span.Span
}

type SwitchCase struct {
	Values  []Expr
	Body    []Statement
	Default bool
	Span    span.Span
}

type Expr struct {
	Kind    string
	Name    string
	Field   string
	Op      string
	Value   string
	Operand *Expr
	Left    *Expr
	Right   *Expr
	Func    *Expr
	Args    []Expr
	Fields  []ExprField
	Span    span.Span
}

type ExprField struct {
	Name  string
	Value Expr
	Span  span.Span
}

type Type struct {
	Name string
	Args []Type
	Len  string
	Elem *Type
	Ptr  bool
}

type Struct struct {
	Name   string
	Fields []Field
	Span   span.Span
	// Origin records the import alias of the dependency package this
	// struct was lowered from (roadmap #20 Phase 2 Subtask 4a). Root-
	// package structs have Origin == "".
	Origin string `json:",omitempty"`
}

type Field struct {
	Name string
	Type Type
	Span span.Span
}
