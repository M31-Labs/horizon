package types

import "m31labs.dev/horizon/ast"

type Env struct {
	decls map[string]ast.Decl
}

func NewEnv() *Env {
	return &Env{decls: make(map[string]ast.Decl)}
}

func (e *Env) Add(name string, decl ast.Decl) {
	e.decls[name] = decl
}

func (e *Env) Decl(name string) (ast.Decl, bool) {
	decl, ok := e.decls[name]
	return decl, ok
}
