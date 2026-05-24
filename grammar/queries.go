package grammar

import _ "embed"

// HighlightsQuery is the default tree-sitter highlight query for .hzn files.
//
//go:embed queries/highlights.scm
var HighlightsQuery string

// LocalsQuery is the default tree-sitter locals query for .hzn files.
//
//go:embed queries/locals.scm
var LocalsQuery string

// SymbolsQuery is the default tree-sitter symbols query for .hzn files.
//
//go:embed queries/symbols.scm
var SymbolsQuery string
