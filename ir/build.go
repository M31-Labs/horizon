package ir

import (
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func FromAST(file ast.File) (Program, []diag.Diagnostic) {
	program := Program{Package: file.Package}
	var diags []diag.Diagnostic
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			program.Structs = append(program.Structs, buildStruct(d))
		case ast.MapDecl:
			program.Maps = append(program.Maps, buildMap(d))
		case ast.FuncDecl:
			fn := buildFunction(d)
			program.Functions = append(program.Functions, fn)
			program.Capabilities = append(program.Capabilities, buildCapabilities(d, fn, program.Maps)...)
		}
	}
	return program, diags
}

func Merge(programs ...Program) Program {
	var merged Program
	for _, program := range programs {
		if merged.Package == "" {
			merged.Package = program.Package
		}
		merged.Structs = append(merged.Structs, program.Structs...)
		merged.Functions = append(merged.Functions, program.Functions...)
		merged.Maps = append(merged.Maps, program.Maps...)
		merged.Capabilities = append(merged.Capabilities, program.Capabilities...)
		merged.SourceMap.Mappings = append(merged.SourceMap.Mappings, program.SourceMap.Mappings...)
	}
	return merged
}

func buildStruct(decl ast.TypeDecl) Struct {
	out := Struct{Name: decl.Name, Span: decl.Span}
	for _, field := range decl.Fields {
		out.Fields = append(out.Fields, Field{
			Name: field.Name,
			Type: buildType(field.Type),
			Span: field.Span,
		})
	}
	return out
}

func buildMap(decl ast.MapDecl) Map {
	return Map{
		Name: decl.Name,
		Kind: MapKind(decl.Kind),
		Key:  buildType(decl.Key),
		Val:  buildType(decl.Val),
	}
}

func buildFunction(decl ast.FuncDecl) Function {
	fn := Function{
		Name:     decl.Name,
		Section:  sectionFromAttrs(decl.Attrs),
		Return:   buildType(decl.Return),
		BodyText: decl.BodyText,
		Span:     decl.Span,
	}
	for _, param := range decl.Params {
		fn.Params = append(fn.Params, Param{Name: param.Name, Type: buildType(param.Type)})
	}
	var block Block
	for _, stmt := range decl.Body {
		block.Statements = append(block.Statements, buildStatement(stmt))
	}
	if len(block.Statements) > 0 {
		fn.Body = append(fn.Body, block)
	}
	return fn
}

func buildStatement(stmt ast.Stmt) Statement {
	switch s := stmt.(type) {
	case ast.ShortVarStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "short_var", Name: s.Name, Value: &value, Span: s.Span}
	case ast.AssignStmt:
		target := buildExpr(s.Target)
		value := buildExpr(s.Value)
		return Statement{Kind: "assign", Target: &target, Value: &value, Span: s.Span}
	case ast.ReturnStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "return", Value: &value, Span: s.Span}
	case ast.IfStmt:
		cond := buildExpr(s.Cond)
		return Statement{Kind: "if", Cond: &cond, Then: buildStatements(s.Then), Span: s.Span}
	case ast.ForStmt:
		init := buildStatementPtr(s.Init)
		cond := buildExpr(s.Cond)
		post := buildStatementPtr(s.Post)
		return Statement{Kind: "for", Init: init, Cond: &cond, Post: post, Body: buildStatements(s.Body), Span: s.Span}
	case ast.ExprStmt:
		expr := buildExpr(s.Expr)
		return Statement{Kind: "expr", Expr: &expr, Span: s.Span}
	case ast.IncStmt:
		return Statement{Kind: "inc", Name: s.Name, Op: s.Op, Span: s.Span}
	case ast.RawStmt:
		return Statement{Kind: "raw", Value: &Expr{Kind: "raw", Value: s.Text, Span: s.Span}, Span: s.Span}
	default:
		return Statement{Kind: "unknown", Span: stmt.GetSpan()}
	}
}

func buildStatementPtr(stmt ast.Stmt) *Statement {
	if stmt == nil {
		return nil
	}
	built := buildStatement(stmt)
	return &built
}

func buildStatements(stmts []ast.Stmt) []Statement {
	out := make([]Statement, 0, len(stmts))
	for _, stmt := range stmts {
		out = append(out, buildStatement(stmt))
	}
	return out
}

func buildExpr(expr ast.Expr) Expr {
	switch e := expr.(type) {
	case nil:
		return Expr{}
	case ast.IdentExpr:
		return Expr{Kind: "ident", Name: e.Name, Span: e.Span}
	case ast.SelectorExpr:
		operand := buildExpr(e.Operand)
		return Expr{Kind: "selector", Operand: &operand, Field: e.Field, Span: e.Span}
	case ast.CallExpr:
		fn := buildExpr(e.Func)
		return Expr{Kind: "call", Func: &fn, Args: buildExprs(e.Args), Span: e.Span}
	case ast.StructLiteralExpr:
		return Expr{Kind: "struct_lit", Name: e.Type.Name, Fields: buildExprFields(e.Fields), Span: e.Span}
	case ast.UnaryExpr:
		operand := buildExpr(e.Expr)
		return Expr{Kind: "unary", Op: e.Op, Operand: &operand, Span: e.Span}
	case ast.BinaryExpr:
		left := buildExpr(e.Left)
		right := buildExpr(e.Right)
		return Expr{Kind: "binary", Op: e.Op, Left: &left, Right: &right, Span: e.Span}
	case ast.IntExpr:
		return Expr{Kind: "int", Value: e.Value, Span: e.Span}
	case ast.NilExpr:
		return Expr{Kind: "nil", Span: e.Span}
	case ast.RawExpr:
		return Expr{Kind: "raw", Value: e.Text, Span: e.Span}
	case ast.StringExpr:
		return Expr{Kind: "string", Value: e.Value, Span: e.Span}
	default:
		return Expr{Kind: "unknown", Span: expr.GetSpan()}
	}
}

func buildExprFields(fields []ast.StructLiteralField) []ExprField {
	out := make([]ExprField, 0, len(fields))
	for _, field := range fields {
		out = append(out, ExprField{
			Name:  field.Name,
			Value: buildExpr(field.Value),
			Span:  field.Span,
		})
	}
	return out
}

func buildExprs(exprs []ast.Expr) []Expr {
	out := make([]Expr, 0, len(exprs))
	for _, expr := range exprs {
		out = append(out, buildExpr(expr))
	}
	return out
}

func buildCapabilities(decl ast.FuncDecl, fn Function, maps []Map) []Capability {
	var out []Capability
	for _, attr := range decl.Attrs {
		if attr.Name != "capability" {
			continue
		}
		name := stringArg(attr)
		access := mapAccesses(fn, maps)
		out = append(out, Capability{
			Name:    name,
			Kind:    CapabilitySource,
			Program: fn.Name,
			Section: manifestSection(fn.Section),
			Emits:   access.Emits,
			Maps:    access.Maps,
			Danger:  DangerObserve,
		})
	}
	return out
}

func buildType(ref ast.TypeRef) Type {
	typ := Type{
		Name: ref.Name,
		Len:  ref.Len,
		Ptr:  ref.Ptr,
	}
	for _, arg := range ref.Args {
		typ.Args = append(typ.Args, buildType(arg))
	}
	if ref.Elem != nil {
		elem := buildType(*ref.Elem)
		typ.Elem = &elem
	}
	return typ
}

func sectionFromAttrs(attrs []ast.Attr) Section {
	for _, attr := range attrs {
		if attr.Name != "tracepoint" {
			continue
		}
		attach := stringArg(attr)
		return Section{
			Kind:   ProgramTracepoint,
			Attach: attach,
			Name:   "tracepoint/" + strings.ReplaceAll(attach, ":", "/"),
		}
	}
	return Section{}
}

func stringArg(attr ast.Attr) string {
	if len(attr.Args) == 0 {
		return ""
	}
	if value, ok := attr.Args[0].(ast.StringExpr); ok {
		return value.Value
	}
	return ""
}

type capabilityAccess struct {
	Maps  CapabilityMapAccess
	Emits string
}

func mapAccesses(fn Function, maps []Map) capabilityAccess {
	byName := map[string]Map{}
	for _, m := range maps {
		byName[m.Name] = m
	}
	seenRead := map[string]bool{}
	seenWrite := map[string]bool{}
	seenEvents := map[string]bool{}
	lookupVars := map[string]string{}
	access := capabilityAccess{
		Maps: CapabilityMapAccess{
			Read:   []string{},
			Write:  []string{},
			Events: []string{},
		},
	}
	var visitExpr func(*Expr)
	visitExpr = func(expr *Expr) {
		if expr == nil {
			return
		}
		if expr.Kind == "call" {
			mapName, method, ok := mapMethodCall(expr)
			if ok {
				m, known := byName[mapName]
				if known {
					switch method {
					case "lookup":
						addUnique(&access.Maps.Read, seenRead, mapName)
					case "update", "delete":
						addUnique(&access.Maps.Write, seenWrite, mapName)
					case "submit":
						if m.Kind == MapKindRingbuf {
							addUnique(&access.Maps.Events, seenEvents, mapName)
							if access.Emits == "" {
								access.Emits = m.Val.Name
							}
						}
					}
				}
			}
		}
		visitExpr(expr.Operand)
		visitExpr(expr.Left)
		visitExpr(expr.Right)
		visitExpr(expr.Func)
		for i := range expr.Args {
			visitExpr(&expr.Args[i])
		}
		for i := range expr.Fields {
			visitExpr(&expr.Fields[i].Value)
		}
	}
	var walk func([]Statement)
	walk = func(stmts []Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var":
				visitExpr(stmt.Value)
				if mapName, method, ok := mapMethodCall(stmt.Value); ok && method == "lookup" {
					if _, known := byName[mapName]; known {
						lookupVars[stmt.Name] = mapName
					}
				}
			case "assign":
				if varName, ok := selectorBase(stmt.Target); ok {
					if mapName, ok := lookupVars[varName]; ok {
						addUnique(&access.Maps.Write, seenWrite, mapName)
					}
				}
				visitExpr(stmt.Target)
				visitExpr(stmt.Value)
			case "expr":
				visitExpr(stmt.Expr)
			case "return":
				visitExpr(stmt.Value)
			case "if":
				visitExpr(stmt.Cond)
				walk(stmt.Then)
			case "for":
				if stmt.Init != nil {
					walk([]Statement{*stmt.Init})
				}
				visitExpr(stmt.Cond)
				if stmt.Post != nil {
					walk([]Statement{*stmt.Post})
				}
				walk(stmt.Body)
			}
		}
	}
	walk(functionStatements(fn))
	return access
}

func mapMethodCall(expr *Expr) (string, string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" {
		return "", "", false
	}
	switch expr.Func.Field {
	case "lookup", "update", "delete", "submit":
		return expr.Func.Operand.Name, expr.Func.Field, true
	default:
		return "", "", false
	}
}

func selectorBase(expr *Expr) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Kind {
	case "ident":
		return expr.Name, true
	case "selector":
		return selectorBase(expr.Operand)
	default:
		return "", false
	}
}

func addUnique(values *[]string, seen map[string]bool, value string) {
	if seen[value] {
		return
	}
	seen[value] = true
	*values = append(*values, value)
}

func functionStatements(fn Function) []Statement {
	var out []Statement
	for _, block := range fn.Body {
		out = append(out, block.Statements...)
	}
	return out
}

func manifestSection(section Section) string {
	if section.Kind == ProgramTracepoint && section.Attach != "" {
		return "tracepoint/" + section.Attach
	}
	return section.Name
}
