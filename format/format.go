package format

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/parser"
)

func Source(src parser.SourceFile) ([]byte, error) {
	if hasLineComment(src.Bytes) {
		return nil, fmt.Errorf("%s: hzn fmt does not preserve line comments yet", src.Path)
	}
	parsed, err := parser.ParseSource(src)
	if err != nil {
		return nil, err
	}
	file, err := ast.Build(parsed)
	if err != nil {
		return nil, err
	}
	return File(*file), nil
}

func File(file ast.File) []byte {
	var b builder
	if file.Package != "" {
		b.line("package " + file.Package)
	}
	if len(file.Imports) > 0 {
		b.blank()
		for _, imp := range file.Imports {
			line := "import "
			if imp.Alias != "" {
				line += imp.Alias + " "
			}
			line += strconv.Quote(imp.Path)
			b.line(line)
		}
	}
	for _, decl := range file.Decls {
		b.blank()
		b.decl(decl)
	}
	out := bytes.TrimRight(b.buf.Bytes(), "\n")
	out = append(out, '\n')
	return out
}

type builder struct {
	buf    bytes.Buffer
	indent int
}

func (b *builder) line(text string) {
	if b.buf.Len() > 0 {
		b.buf.WriteByte('\n')
	}
	for i := 0; i < b.indent; i++ {
		b.buf.WriteString("    ")
	}
	b.buf.WriteString(text)
}

func (b *builder) blank() {
	if b.buf.Len() == 0 {
		return
	}
	data := b.buf.Bytes()
	if len(data) >= 2 && data[len(data)-1] == '\n' && data[len(data)-2] == '\n' {
		return
	}
	b.buf.WriteByte('\n')
}

func (b *builder) decl(decl ast.Decl) {
	switch d := decl.(type) {
	case ast.TypeDecl:
		b.typeDecl(d)
	case ast.ConstDecl:
		line := "const " + d.Name
		if !d.Type.IsZero() {
			line += " " + typeRef(d.Type)
		}
		line += " = " + expr(d.Value)
		b.line(line)
	case ast.MapDecl:
		b.line("map " + d.Name + " " + mapType(d))
	case ast.FuncDecl:
		for _, attr := range d.Attrs {
			b.line(attrText(attr))
		}
		params := make([]string, 0, len(d.Params))
		for _, param := range d.Params {
			params = append(params, param.Name+" "+typeRef(param.Type))
		}
		line := "func " + d.Name + "(" + strings.Join(params, ", ") + ")"
		if !d.Return.IsZero() {
			line += " " + typeRef(d.Return)
		}
		b.line(line + " {")
		b.indent++
		b.stmts(d.Body)
		b.indent--
		b.line("}")
	}
}

func (b *builder) typeDecl(decl ast.TypeDecl) {
	b.line("type " + decl.Name + " struct {")
	b.indent++
	for _, field := range decl.Fields {
		b.line(field.Name + " " + typeRef(field.Type))
	}
	b.indent--
	b.line("}")
}

func (b *builder) stmts(stmts []ast.Stmt) {
	for _, stmt := range stmts {
		b.stmt(stmt)
	}
}

func (b *builder) stmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case ast.ShortVarStmt:
		b.line(s.Name + " := " + expr(s.Value))
	case ast.AssignStmt:
		b.line(expr(s.Target) + " = " + expr(s.Value))
	case ast.ReturnStmt:
		if s.Value == nil {
			b.line("return")
			return
		}
		b.line("return " + expr(s.Value))
	case ast.ExprStmt:
		b.line(expr(s.Expr))
	case ast.IncStmt:
		b.line(s.Name + s.Op)
	case ast.IfStmt:
		b.ifStmt(s)
	case ast.ForStmt:
		b.forStmt(s)
	case ast.RawStmt:
		b.line(s.Text)
	}
}

func (b *builder) ifStmt(stmt ast.IfStmt) {
	b.line("if " + expr(stmt.Cond) + " {")
	b.indent++
	b.stmts(stmt.Then)
	b.indent--
	if len(stmt.Else) == 1 {
		if nested, ok := stmt.Else[0].(ast.IfStmt); ok {
			b.line("} else " + ifHeader(nested))
			b.indent++
			b.stmts(nested.Then)
			b.indent--
			b.emitElse(nested.Else)
			return
		}
	}
	if len(stmt.Else) > 0 {
		b.line("} else {")
		b.indent++
		b.stmts(stmt.Else)
		b.indent--
		b.line("}")
		return
	}
	b.line("}")
}

func (b *builder) emitElse(stmts []ast.Stmt) {
	if len(stmts) == 1 {
		if nested, ok := stmts[0].(ast.IfStmt); ok {
			b.line("} else " + ifHeader(nested))
			b.indent++
			b.stmts(nested.Then)
			b.indent--
			b.emitElse(nested.Else)
			return
		}
	}
	if len(stmts) > 0 {
		b.line("} else {")
		b.indent++
		b.stmts(stmts)
		b.indent--
		b.line("}")
		return
	}
	b.line("}")
}

func ifHeader(stmt ast.IfStmt) string {
	return "if " + expr(stmt.Cond) + " {"
}

func (b *builder) forStmt(stmt ast.ForStmt) {
	header := "for"
	switch {
	case stmt.Init != nil || stmt.Post != nil:
		header += " " + simpleStmt(stmt.Init) + "; " + expr(stmt.Cond) + "; " + simpleStmt(stmt.Post)
	case stmt.Cond != nil:
		header += " " + expr(stmt.Cond)
	}
	b.line(header + " {")
	b.indent++
	b.stmts(stmt.Body)
	b.indent--
	b.line("}")
}

func simpleStmt(stmt ast.Stmt) string {
	switch s := stmt.(type) {
	case nil:
		return ""
	case ast.ShortVarStmt:
		return s.Name + " := " + expr(s.Value)
	case ast.AssignStmt:
		return expr(s.Target) + " = " + expr(s.Value)
	case ast.IncStmt:
		return s.Name + s.Op
	case ast.ExprStmt:
		return expr(s.Expr)
	default:
		return ""
	}
}

func attrText(attr ast.Attr) string {
	if len(attr.Args) == 0 {
		return "@" + attr.Name
	}
	args := make([]string, 0, len(attr.Args))
	for _, arg := range attr.Args {
		args = append(args, expr(arg))
	}
	return "@" + attr.Name + "(" + strings.Join(args, ", ") + ")"
}

func mapType(decl ast.MapDecl) string {
	switch decl.Kind {
	case ast.MapKindRingbuf:
		return "ringbuf[" + typeRef(decl.Val) + "]"
	case ast.MapKindHash:
		return "hash[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
	case ast.MapKindArray:
		return "array[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
	default:
		return string(decl.Kind)
	}
}

func typeRef(t ast.TypeRef) string {
	switch {
	case t.Ptr && t.Elem != nil:
		return "*" + typeRef(*t.Elem)
	case t.Len != "" && t.Elem != nil:
		return "[" + t.Len + "]" + typeRef(*t.Elem)
	case len(t.Args) > 0:
		args := make([]string, 0, len(t.Args))
		for _, arg := range t.Args {
			args = append(args, typeRef(arg))
		}
		return t.Name + "[" + strings.Join(args, ", ") + "]"
	default:
		return t.Name
	}
}

func expr(e ast.Expr) string {
	return exprPrec(e, 0)
}

func exprPrec(e ast.Expr, parent int) string {
	switch v := e.(type) {
	case nil:
		return ""
	case ast.IdentExpr:
		return v.Name
	case ast.IntExpr:
		return v.Value
	case ast.BoolExpr:
		if v.Value {
			return "true"
		}
		return "false"
	case ast.NilExpr:
		return "nil"
	case ast.StringExpr:
		return strconv.Quote(v.Value)
	case ast.RawExpr:
		return v.Text
	case ast.SelectorExpr:
		return exprPrec(v.Operand, 10) + "." + v.Field
	case ast.CallExpr:
		args := make([]string, 0, len(v.Args))
		for _, arg := range v.Args {
			args = append(args, expr(arg))
		}
		return exprPrec(v.Func, 10) + "(" + strings.Join(args, ", ") + ")"
	case ast.StructLiteralExpr:
		fields := make([]string, 0, len(v.Fields))
		for _, field := range v.Fields {
			fields = append(fields, field.Name+": "+expr(field.Value))
		}
		return typeRef(v.Type) + "{" + strings.Join(fields, ", ") + "}"
	case ast.UnaryExpr:
		text := v.Op + exprPrec(v.Expr, 9)
		if 9 < parent {
			return "(" + text + ")"
		}
		return text
	case ast.BinaryExpr:
		prec := binaryPrecedence(v.Op)
		text := exprPrec(v.Left, prec) + " " + v.Op + " " + exprPrec(v.Right, prec+1)
		if prec < parent {
			return "(" + text + ")"
		}
		return text
	default:
		return ""
	}
}

func binaryPrecedence(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "==", "!=", "<", "<=", ">", ">=":
		return 3
	case "|":
		return 4
	case "^":
		return 5
	case "&":
		return 6
	case "<<", ">>":
		return 7
	case "+", "-":
		return 8
	case "*", "/", "%":
		return 9
	default:
		return 0
	}
}

func hasLineComment(source []byte) bool {
	inString := false
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '"':
			inString = !inString
		case '/':
			if !inString && i+1 < len(source) && source[i+1] == '/' {
				return true
			}
		}
	}
	return false
}
