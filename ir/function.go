package ir

import "m31labs.dev/horizon/compiler/span"

type Function struct {
	Name    string
	Section Section
	Params  []Param
	Return  Type
	Body    []Block
	Span    span.Span
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
	Span span.Span
}

type Type struct {
	Name string
}
