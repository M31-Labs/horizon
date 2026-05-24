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

type ShortVarStmt struct {
	Name  string
	Value Expr
	Span  span.Span
}

func (ShortVarStmt) stmtNode() {}
func (s ShortVarStmt) GetSpan() span.Span {
	return s.Span
}

type VarDeclStmt struct {
	Name  string
	Type  TypeRef
	Value Expr
	Span  span.Span
}

func (VarDeclStmt) stmtNode() {}
func (s VarDeclStmt) GetSpan() span.Span {
	return s.Span
}

type AssignStmt struct {
	Target Expr
	Value  Expr
	Span   span.Span
}

func (AssignStmt) stmtNode() {}
func (s AssignStmt) GetSpan() span.Span {
	return s.Span
}

type ReturnStmt struct {
	Value Expr
	Span  span.Span
}

func (ReturnStmt) stmtNode() {}
func (s ReturnStmt) GetSpan() span.Span {
	return s.Span
}

type IfStmt struct {
	Init Stmt
	Cond Expr
	Then []Stmt
	Else []Stmt
	Span span.Span
}

func (IfStmt) stmtNode() {}
func (s IfStmt) GetSpan() span.Span {
	return s.Span
}

type ForStmt struct {
	Init Stmt
	Cond Expr
	Post Stmt
	Body []Stmt
	Span span.Span
}

func (ForStmt) stmtNode() {}
func (s ForStmt) GetSpan() span.Span {
	return s.Span
}

type SwitchStmt struct {
	Value Expr
	Cases []SwitchCase
	Span  span.Span
}

func (SwitchStmt) stmtNode() {}
func (s SwitchStmt) GetSpan() span.Span {
	return s.Span
}

type SwitchCase struct {
	Values  []Expr
	Body    []Stmt
	Default bool
	Span    span.Span
}

type ExprStmt struct {
	Expr Expr
	Span span.Span
}

func (ExprStmt) stmtNode() {}
func (s ExprStmt) GetSpan() span.Span {
	return s.Span
}

type IncStmt struct {
	Name string
	Op   string
	Span span.Span
}

func (IncStmt) stmtNode() {}
func (s IncStmt) GetSpan() span.Span {
	return s.Span
}
