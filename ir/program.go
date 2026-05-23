package ir

import "m31labs.dev/horizon/compiler/span"

type Program struct {
	Package      string
	Structs      []Struct
	Functions    []Function
	Maps         []Map
	Capabilities []Capability
	SourceMap    SourceMap
}

type SourceMap struct {
	Mappings []SourceMapping `json:"mappings"`
}

type SourceMapping struct {
	Source    span.Span `json:"source"`
	Generated span.Span `json:"generated"`
	Node      string    `json:"node"`
	Function  string    `json:"function"`
	Section   string    `json:"section"`
}
