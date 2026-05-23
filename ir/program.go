package ir

import "m31labs.dev/horizon/compiler/span"

type Program struct {
	Package      string
	Functions    []Function
	Maps         []Map
	Capabilities []Capability
	SourceMap    SourceMap
}

type SourceMap struct {
	Mappings []SourceMapping
}

type SourceMapping struct {
	Source    span.Span
	Generated span.Span
	Node      string
	Function  string
	Section   string
}
