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
}

type Param struct {
	Name string
	Type Type
}

type Block struct {
	Statements []Statement
}

type Statement struct {
	Kind string
	Text string
	Span span.Span
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
}

type Field struct {
	Name string
	Type Type
	Span span.Span
}
