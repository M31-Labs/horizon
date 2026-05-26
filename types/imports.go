package types

import "m31labs.dev/horizon/ast"

// ImportGraph is the cross-package resolution view consumed by CheckPackages.
// It mirrors the shape of compiler.ImportGraph but lives in types/ to avoid
// an import cycle (compiler imports types). The compiler builds the concrete
// graph during ResolveImports and converts it via ToTypesGraph before passing
// it down.
//
// Edges is keyed by importer package directory → local alias → resolved
// dependency directory (or canonical builtin path for builtin aliases).
// Packages is keyed by resolved directory (or canonical builtin path) and
// holds the parsed ast.Package for that directory. BuiltinAliases is the
// union of all aliases (across importers) that resolve to a compiler builtin
// namespace such as bpf, xdp, etc. — these route through compilerNamespace
// instead of being looked up as user packages.
//
// (roadmap #20 — Phase 2 Subtask 3b.)
type ImportGraph struct {
	Edges          map[string]map[string]string
	Packages       map[string]ast.Package
	BuiltinAliases map[string]bool
}
