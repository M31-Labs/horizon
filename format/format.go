package format

import (
	"bytes"
	"strconv"
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/parser"
)

func Source(src parser.SourceFile) ([]byte, error) {
	comments, err := lineComments(src)
	if err != nil {
		return nil, err
	}
	parsed, err := parser.ParseSource(src)
	if err != nil {
		return nil, err
	}
	file, err := ast.Build(parsed)
	if err != nil {
		return nil, err
	}
	return formatFile(*file, comments, packageLine(src.Bytes)), nil
}

func File(file ast.File) []byte {
	return formatFile(file, nil, 0)
}

func formatFile(file ast.File, comments []lineComment, packageLine int) []byte {
	var b builder
	b.comments = comments
	if packageLine > 0 {
		b.flushCommentsBefore(packageLine)
	}
	if file.Package != "" {
		b.lineWithComment("package "+file.Package, packageLine)
	}
	if len(file.Imports) > 0 {
		b.blank()
		for _, imp := range file.Imports {
			b.flushCommentsBefore(imp.Span.Start.Line)
			line := "import "
			if imp.Alias != "" {
				line += imp.Alias + " "
			}
			line += strconv.Quote(imp.Path)
			b.lineWithComment(line, imp.Span.Start.Line)
		}
	}
	for _, decl := range file.Decls {
		b.blank()
		b.decl(decl)
	}
	b.flushRemainingComments()
	out := bytes.TrimRight(b.buf.Bytes(), "\n")
	out = append(out, '\n')
	return out
}

type builder struct {
	buf      bytes.Buffer
	indent   int
	comments []lineComment
	next     int
}

func (b *builder) line(text string) {
	b.writeLine(text)
}

func (b *builder) lineWithComment(text string, line int) {
	if line > 0 {
		b.flushCommentsBefore(line)
	}
	if comment, ok := b.takeInlineComment(line); ok {
		text += " " + comment
	}
	b.writeLine(text)
}

func (b *builder) lineWithNextInlineBefore(text string, beforeLine int) {
	if beforeLine > 0 && b.next < len(b.comments) {
		comment := b.comments[b.next]
		if comment.Inline && comment.Line < beforeLine {
			text += " " + comment.Text
			b.next++
		}
	}
	b.writeLine(text)
}

func (b *builder) writeLine(text string) {
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

func (b *builder) comment(text string) {
	b.line(text)
}

func (b *builder) flushCommentsBefore(line int) {
	if line <= 0 {
		return
	}
	for b.next < len(b.comments) && b.comments[b.next].Line < line {
		b.comment(b.comments[b.next].Text)
		b.next++
	}
}

func (b *builder) takeInlineComment(line int) (string, bool) {
	if line <= 0 || b.next >= len(b.comments) {
		return "", false
	}
	comment := b.comments[b.next]
	if comment.Line != line || !comment.Inline {
		return "", false
	}
	b.next++
	return comment.Text, true
}

func (b *builder) flushRemainingComments() {
	for b.next < len(b.comments) {
		b.comment(b.comments[b.next].Text)
		b.next++
	}
}

func (b *builder) decl(decl ast.Decl) {
	b.flushCommentsBefore(decl.GetSpan().Start.Line)
	switch d := decl.(type) {
	case ast.TypeDecl:
		b.typeDecl(d)
	case ast.ConstDecl:
		line := "const " + d.Name
		if !d.Type.IsZero() {
			line += " " + typeRef(d.Type)
		}
		line += " = " + expr(d.Value)
		b.lineWithComment(line, d.Span.Start.Line)
	case ast.EnumDecl:
		b.lineWithComment("enum "+d.Name+" "+typeRef(d.Type)+" {", d.Span.Start.Line)
		b.indent++
		for _, value := range d.Values {
			b.flushCommentsBefore(value.Span.Start.Line)
			b.lineWithComment(value.Name+" = "+expr(value.Value), value.Span.Start.Line)
		}
		b.flushCommentsBefore(d.Span.End.Line)
		b.indent--
		b.lineWithComment("}", d.Span.End.Line)
	case ast.CapabilityDecl:
		b.lineWithComment("capability "+d.Name+" = "+strconv.Quote(d.Value), d.Span.Start.Line)
	case ast.MapDecl:
		for _, attr := range d.Attrs {
			b.lineWithComment(attrText(attr), attr.Span.Start.Line)
		}
		b.lineWithComment("map "+d.Name+" "+mapType(d), mapLine(d))
	case ast.FuncDecl:
		for _, attr := range d.Attrs {
			b.lineWithComment(attrText(attr), attr.Span.Start.Line)
		}
		params := make([]string, 0, len(d.Params))
		for _, param := range d.Params {
			params = append(params, param.Name+" "+typeRef(param.Type))
		}
		line := "func " + d.Name + "(" + strings.Join(params, ", ") + ")"
		if !d.Return.IsZero() {
			line += " " + typeRef(d.Return)
		}
		b.lineWithComment(line+" {", funcHeaderLine(d))
		b.indent++
		b.stmts(d.Body)
		b.flushCommentsBefore(d.Span.End.Line)
		b.indent--
		b.lineWithComment("}", d.Span.End.Line)
	}
}

func mapLine(decl ast.MapDecl) int {
	if decl.Key.Span.Start.Line > 0 {
		return decl.Key.Span.Start.Line
	}
	if decl.Val.Span.Start.Line > 0 {
		return decl.Val.Span.Start.Line
	}
	return decl.Span.Start.Line
}

func funcHeaderLine(decl ast.FuncDecl) int {
	if len(decl.Params) > 0 && decl.Params[0].Span.Start.Line > 0 {
		return decl.Params[0].Span.Start.Line
	}
	if !decl.Return.IsZero() && decl.Return.Span.Start.Line > 0 {
		return decl.Return.Span.Start.Line
	}
	if len(decl.Attrs) > 0 {
		return decl.Attrs[len(decl.Attrs)-1].Span.End.Line + 1
	}
	return decl.Span.Start.Line
}

func (b *builder) typeDecl(decl ast.TypeDecl) {
	if decl.IsAlias() {
		b.lineWithComment("type "+decl.Name+" = "+typeRef(decl.Alias), decl.Span.Start.Line)
		return
	}
	b.lineWithComment("type "+decl.Name+" struct {", decl.Span.Start.Line)
	b.indent++
	for _, field := range decl.Fields {
		b.flushCommentsBefore(field.Span.Start.Line)
		b.lineWithComment(field.Name+" "+typeRef(field.Type), field.Span.Start.Line)
	}
	b.flushCommentsBefore(decl.Span.End.Line)
	b.indent--
	b.lineWithComment("}", decl.Span.End.Line)
}

func (b *builder) stmts(stmts []ast.Stmt) {
	for _, stmt := range stmts {
		b.stmt(stmt)
	}
}

func (b *builder) stmt(stmt ast.Stmt) {
	b.flushCommentsBefore(stmt.GetSpan().Start.Line)
	switch s := stmt.(type) {
	case ast.ShortVarStmt:
		b.lineWithComment(s.Name+" := "+expr(s.Value), s.Span.Start.Line)
	case ast.VarDeclStmt:
		b.lineWithComment("var "+s.Name+" "+typeRef(s.Type)+" = "+expr(s.Value), s.Span.Start.Line)
	case ast.AssignStmt:
		b.lineWithComment(expr(s.Target)+" = "+expr(s.Value), s.Span.Start.Line)
	case ast.ReturnStmt:
		if s.Value == nil {
			b.lineWithComment("return", s.Span.Start.Line)
			return
		}
		b.lineWithComment("return "+expr(s.Value), s.Span.Start.Line)
	case ast.ExprStmt:
		b.lineWithComment(expr(s.Expr), s.Span.Start.Line)
	case ast.IncStmt:
		b.lineWithComment(s.Name+s.Op, s.Span.Start.Line)
	case ast.IfStmt:
		b.ifStmt(s)
	case ast.ForStmt:
		b.forStmt(s)
	case ast.SwitchStmt:
		b.switchStmt(s)
	case ast.RawStmt:
		b.lineWithComment(s.Text, s.Span.Start.Line)
	}
}

func (b *builder) ifStmt(stmt ast.IfStmt) {
	b.lineWithComment(ifHeader(stmt), stmt.Span.Start.Line)
	b.indent++
	b.stmts(stmt.Then)
	if len(stmt.Else) == 0 {
		b.flushCommentsBefore(stmt.Span.End.Line)
	}
	b.indent--
	if len(stmt.Else) == 1 {
		if nested, ok := stmt.Else[0].(ast.IfStmt); ok {
			b.lineWithComment("} else "+ifHeader(nested), nested.Span.Start.Line)
			b.indent++
			b.stmts(nested.Then)
			if len(nested.Else) == 0 {
				b.flushCommentsBefore(nested.Span.End.Line)
			}
			b.indent--
			b.emitElse(nested.Else)
			return
		}
	}
	if len(stmt.Else) > 0 {
		b.lineWithNextInlineBefore("} else {", stmt.Else[0].GetSpan().Start.Line)
		b.indent++
		b.stmts(stmt.Else)
		b.flushCommentsBefore(stmt.Span.End.Line)
		b.indent--
		b.lineWithComment("}", stmt.Span.End.Line)
		return
	}
	b.lineWithComment("}", stmt.Span.End.Line)
}

func (b *builder) switchStmt(stmt ast.SwitchStmt) {
	b.lineWithComment("switch "+expr(stmt.Value)+" {", stmt.Span.Start.Line)
	b.indent++
	for _, c := range stmt.Cases {
		b.flushCommentsBefore(c.Span.Start.Line)
		if c.Default {
			b.lineWithComment("default:", c.Span.Start.Line)
		} else {
			values := make([]string, 0, len(c.Values))
			for _, value := range c.Values {
				values = append(values, expr(value))
			}
			b.lineWithComment("case "+strings.Join(values, ", ")+":", c.Span.Start.Line)
		}
		b.indent++
		b.stmts(c.Body)
		b.indent--
	}
	b.flushCommentsBefore(stmt.Span.End.Line)
	b.indent--
	b.lineWithComment("}", stmt.Span.End.Line)
}

func (b *builder) emitElse(stmts []ast.Stmt) {
	if len(stmts) == 1 {
		if nested, ok := stmts[0].(ast.IfStmt); ok {
			b.lineWithComment("} else "+ifHeader(nested), nested.Span.Start.Line)
			b.indent++
			b.stmts(nested.Then)
			if len(nested.Else) == 0 {
				b.flushCommentsBefore(nested.Span.End.Line)
			}
			b.indent--
			b.emitElse(nested.Else)
			return
		}
	}
	if len(stmts) > 0 {
		b.lineWithNextInlineBefore("} else {", stmts[0].GetSpan().Start.Line)
		b.indent++
		b.stmts(stmts)
		b.flushCommentsBefore(stmts[len(stmts)-1].GetSpan().End.Line)
		b.indent--
		b.lineWithComment("}", stmts[len(stmts)-1].GetSpan().End.Line)
		return
	}
	b.line("}")
}

func ifHeader(stmt ast.IfStmt) string {
	header := "if "
	if stmt.Init != nil {
		header += simpleStmt(stmt.Init) + "; "
	}
	return header + expr(stmt.Cond) + " {"
}

func (b *builder) forStmt(stmt ast.ForStmt) {
	header := "for"
	switch {
	case stmt.Init != nil || stmt.Post != nil:
		header += " " + simpleStmt(stmt.Init) + "; " + expr(stmt.Cond) + "; " + simpleStmt(stmt.Post)
	case stmt.Cond != nil:
		header += " " + expr(stmt.Cond)
	}
	b.lineWithComment(header+" {", stmt.Span.Start.Line)
	b.indent++
	b.stmts(stmt.Body)
	b.flushCommentsBefore(stmt.Span.End.Line)
	b.indent--
	b.lineWithComment("}", stmt.Span.End.Line)
}

func simpleStmt(stmt ast.Stmt) string {
	switch s := stmt.(type) {
	case nil:
		return ""
	case ast.ShortVarStmt:
		return s.Name + " := " + expr(s.Value)
	case ast.VarDeclStmt:
		return "var " + s.Name + " " + typeRef(s.Type) + " = " + expr(s.Value)
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
	case ast.MapKindPerCPUHash:
		return "percpu_hash[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
	case ast.MapKindPerCPUArray:
		return "percpu_array[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
	case ast.MapKindLRUHash:
		return "lru_hash[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
	case ast.MapKindLRUPerCPU:
		return "lru_percpu_hash[" + typeRef(decl.Key) + ", " + typeRef(decl.Val) + "]"
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
		operand := exprPrec(v.Expr, 9)
		if _, nested := v.Expr.(ast.UnaryExpr); nested {
			operand = "(" + expr(v.Expr) + ")"
		}
		text := v.Op + operand
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

type lineComment struct {
	Line   int
	Text   string
	Inline bool
}

func lineComments(src parser.SourceFile) ([]lineComment, error) {
	lines := strings.Split(string(src.Bytes), "\n")
	comments := make([]lineComment, 0)
	for i, line := range lines {
		idx := lineCommentIndex(line)
		if idx < 0 {
			continue
		}
		comments = append(comments, lineComment{
			Line:   i + 1,
			Text:   strings.TrimSpace(line[idx:]),
			Inline: strings.TrimSpace(line[:idx]) != "",
		})
	}
	return comments, nil
}

func lineCommentIndex(line string) int {
	inString := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inString = !inString
		case '/':
			if !inString && i+1 < len(line) && line[i+1] == '/' {
				return i
			}
		}
	}
	return -1
}

func packageLine(source []byte) int {
	lines := strings.Split(string(source), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "package ") || trimmed == "package" {
			return i + 1
		}
		return 0
	}
	return 0
}
