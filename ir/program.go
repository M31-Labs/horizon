package ir

import "m31labs.dev/horizon/compiler/span"

type Program struct {
	Package      string
	Constants    []Const
	Structs      []Struct
	Functions    []Function
	Maps         []Map
	Capabilities []Capability
}

type Const struct {
	Name  string
	Type  Type
	Value Expr
	Span  span.Span
	// Origin records the import alias of the dependency package this
	// constant was lowered from (roadmap #20 Phase 2 Subtask 4a). Root-
	// package constants have Origin == "".
	Origin string `json:",omitempty"`
}

// SourceMap describes the mapping from .hzn source spans to generated C
// lines. Populated by emitc.Emit (which sets emitc.Output.SourceMap) and
// consumed by verifier.Remap and cmd/hzn diagnostics. Kept in ir/ as the
// neutral lowest-common-ancestor package shared by emitc, verifier, and cmd/hzn.
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
