package ir

import "m31labs.dev/horizon/compiler/span"

type Program struct {
	Package      string
	Constants    []Const
	Structs      []Struct
	Functions    []Function
	Maps         []Map
	Capabilities []Capability
	SourceMap    SourceMap
}

type Const struct {
	Name  string
	Type  Type
	Value Expr
	Span  span.Span
}

type SourceMap struct {
	Schema    string          `json:"schema"`
	Sources   []Source        `json:"sources,omitempty"`
	Generated GeneratedSource `json:"generated,omitempty"`
	Mappings  []SourceMapping `json:"mappings"`
}

type SourceMapping struct {
	Source    span.Span `json:"source"`
	Generated span.Span `json:"generated"`
	Node      string    `json:"node"`
	Function  string    `json:"function"`
	Section   string    `json:"section"`
}

type Source struct {
	ID   int    `json:"id"`
	Path string `json:"path"`
}

type GeneratedSource struct {
	Path     string `json:"path,omitempty"`
	Language string `json:"language,omitempty"`
}
