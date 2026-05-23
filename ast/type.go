package ast

import "m31labs.dev/horizon/compiler/span"

type TypeRef struct {
	Name string
	Args []TypeRef
	Len  string
	Elem *TypeRef
	Ptr  bool
	Span span.Span
}

func (t TypeRef) IsZero() bool {
	return t.Name == "" && len(t.Args) == 0 && t.Len == "" && t.Elem == nil && !t.Ptr
}
