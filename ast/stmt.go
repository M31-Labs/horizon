package ast

import "m31labs.dev/horizon/compiler/span"

type Stmt interface {
	stmtNode()
	GetSpan() span.Span
}

type RawStmt struct {
	Text string
	Span span.Span
}

func (RawStmt) stmtNode() {}
func (s RawStmt) GetSpan() span.Span {
	return s.Span
}
