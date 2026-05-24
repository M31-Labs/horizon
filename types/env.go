package types

import "m31labs.dev/horizon/compiler/span"

type DeclRef interface {
	GetSpan() span.Span
}

type Env struct {
	decls map[string]DeclRef
}

func NewEnv() *Env {
	return &Env{decls: make(map[string]DeclRef)}
}

func (e *Env) Add(name string, decl DeclRef) {
	e.decls[name] = decl
}

func (e *Env) Decl(name string) (DeclRef, bool) {
	decl, ok := e.decls[name]
	return decl, ok
}
