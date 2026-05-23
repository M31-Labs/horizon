package ast

import "m31labs.dev/horizon/compiler/span"

type Expr interface {
	exprNode()
	GetSpan() span.Span
}

type RawExpr struct {
	Text string
	Span span.Span
}

func (RawExpr) exprNode() {}
func (e RawExpr) GetSpan() span.Span {
	return e.Span
}

type StringExpr struct {
	Value string
	Span  span.Span
}

func (StringExpr) exprNode() {}
func (e StringExpr) GetSpan() span.Span {
	return e.Span
}
