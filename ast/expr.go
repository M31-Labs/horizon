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

type IdentExpr struct {
	Name string
	Span span.Span
}

func (IdentExpr) exprNode() {}
func (e IdentExpr) GetSpan() span.Span {
	return e.Span
}

type SelectorExpr struct {
	Operand Expr
	Field   string
	Span    span.Span
}

func (SelectorExpr) exprNode() {}
func (e SelectorExpr) GetSpan() span.Span {
	return e.Span
}

type CallExpr struct {
	Func Expr
	Args []Expr
	Span span.Span
}

func (CallExpr) exprNode() {}
func (e CallExpr) GetSpan() span.Span {
	return e.Span
}

type UnaryExpr struct {
	Op   string
	Expr Expr
	Span span.Span
}

func (UnaryExpr) exprNode() {}
func (e UnaryExpr) GetSpan() span.Span {
	return e.Span
}

type BinaryExpr struct {
	Left  Expr
	Op    string
	Right Expr
	Span  span.Span
}

func (BinaryExpr) exprNode() {}
func (e BinaryExpr) GetSpan() span.Span {
	return e.Span
}

type IntExpr struct {
	Value string
	Span  span.Span
}

func (IntExpr) exprNode() {}
func (e IntExpr) GetSpan() span.Span {
	return e.Span
}

type NilExpr struct {
	Span span.Span
}

func (NilExpr) exprNode() {}
func (e NilExpr) GetSpan() span.Span {
	return e.Span
}
