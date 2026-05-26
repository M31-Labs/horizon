package ast

import (
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/parser"
)

func Build(parsed *parser.File) (*File, error) {
	root := parsed.Tree.RootNode()
	file := &File{
		Package: parsed.Package,
		Span:    spanForNode(parsed.Source.FileID, root),
	}
	for i := 0; i < int(root.NamedChildCount()); i++ {
		child := root.NamedChild(i)
		switch child.Type(parsed.Lang) {
		case "import_declaration":
			file.Imports = append(file.Imports, buildImport(parsed, child))
		case "type_declaration":
			file.Decls = append(file.Decls, buildTypeDecl(parsed, child))
		case "map_declaration":
			file.Decls = append(file.Decls, buildMapDecl(parsed, child))
		case "function_declaration":
			file.Decls = append(file.Decls, buildFuncDecl(parsed, child))
		case "const_declaration":
			file.Decls = append(file.Decls, buildConstDecl(parsed, child))
		case "enum_declaration":
			file.Decls = append(file.Decls, buildEnumDecl(parsed, child))
		case "capability_declaration":
			file.Decls = append(file.Decls, buildCapabilityDecl(parsed, child))
		}
	}
	return file, nil
}

func buildImport(parsed *parser.File, n *gotreesitter.Node) ImportDecl {
	return ImportDecl{
		Alias: text(parsed, n.ChildByFieldName("alias", parsed.Lang)),
		Path:  strings.Trim(text(parsed, n.ChildByFieldName("path", parsed.Lang)), `"`),
		Span:  spanForNode(parsed.Source.FileID, n),
	}
}

func buildTypeDecl(parsed *parser.File, n *gotreesitter.Node) Decl {
	specs := namedDescendantsOfType(parsed, n, "type_spec")
	if len(specs) == 1 && !hasDirectToken(parsed, n, "(") {
		return buildTypeSpec(parsed, specs[0])
	}
	group := TypeGroupDecl{Span: spanForNode(parsed.Source.FileID, n)}
	for _, spec := range specs {
		group.Types = append(group.Types, buildTypeSpec(parsed, spec))
	}
	return group
}

func buildTypeSpec(parsed *parser.File, n *gotreesitter.Node) TypeDecl {
	decl := TypeDecl{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	if typ := n.ChildByFieldName("type", parsed.Lang); typ != nil {
		if typ.Type(parsed.Lang) != "struct_type" {
			decl.Alias = buildTypeRef(parsed, typ)
			return decl
		}
		for _, child := range namedDescendantsOfType(parsed, typ, "field_declaration") {
			decl.Fields = append(decl.Fields, Field{
				Name: text(parsed, child.ChildByFieldName("name", parsed.Lang)),
				Type: buildTypeRef(parsed, child.ChildByFieldName("type", parsed.Lang)),
				Span: spanForNode(parsed.Source.FileID, child),
			})
		}
	}
	return decl
}

func buildMapDecl(parsed *parser.File, n *gotreesitter.Node) MapDecl {
	typ := buildTypeRef(parsed, n.ChildByFieldName("type", parsed.Lang))
	decl := MapDecl{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) == "attribute" {
			attr := buildAttr(parsed, child)
			decl.Attrs = append(decl.Attrs, attr)
			switch attr.Name {
			case "max_entries":
				if len(attr.Args) == 1 {
					switch value := attr.Args[0].(type) {
					case IntExpr:
						decl.MaxEntries = value.Value
					case IdentExpr:
						decl.MaxEntries = value.Name
					}
				}
			case "steady_state_entries":
				if len(attr.Args) == 1 {
					switch value := attr.Args[0].(type) {
					case IntExpr:
						decl.SteadyStateEntries = value.Value
					case IdentExpr:
						decl.SteadyStateEntries = value.Name
					}
				}
			case "access_freq":
				if len(attr.Args) == 1 {
					if value, ok := attr.Args[0].(StringExpr); ok {
						decl.AccessFreq = value.Value
					}
				}
			}
		}
	}
	if typ.Name != "" {
		decl.Kind = MapKind(typ.Name)
	}
	switch len(typ.Args) {
	case 1:
		decl.Val = typ.Args[0]
	case 2:
		decl.Key = typ.Args[0]
		decl.Val = typ.Args[1]
	}
	return decl
}

func buildFuncDecl(parsed *parser.File, n *gotreesitter.Node) FuncDecl {
	decl := FuncDecl{
		Name:   text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Return: buildTypeRef(parsed, n.ChildByFieldName("return", parsed.Lang)),
		Span:   spanForNode(parsed.Source.FileID, n),
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) == "attribute" {
			decl.Attrs = append(decl.Attrs, buildAttr(parsed, child))
		}
	}
	if params := firstNamedDescendantOfType(parsed, n, "parameter_list"); params != nil {
		for _, child := range namedDescendantsOfType(parsed, params, "parameter") {
			decl.Params = append(decl.Params, Param{
				Name: text(parsed, child.ChildByFieldName("name", parsed.Lang)),
				Type: buildTypeRef(parsed, child.ChildByFieldName("type", parsed.Lang)),
				Span: spanForNode(parsed.Source.FileID, child),
			})
		}
	}
	if body := n.ChildByFieldName("body", parsed.Lang); body != nil {
		decl.BodyText = blockBodyText(parsed, body)
		decl.Body = buildBlockStatements(parsed, body)
	}
	return decl
}

func blockBodyText(parsed *parser.File, n *gotreesitter.Node) string {
	raw := strings.TrimSpace(text(parsed, n))
	if strings.HasPrefix(raw, "{") {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "{"))
	}
	if strings.HasSuffix(raw, "}") {
		raw = strings.TrimSpace(strings.TrimSuffix(raw, "}"))
	}
	return raw
}

func buildAttr(parsed *parser.File, n *gotreesitter.Node) Attr {
	attr := Attr{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	if value := n.ChildByFieldName("value", parsed.Lang); value != nil {
		attr.Args = append(attr.Args, buildAttributeValue(parsed, value))
	}
	return attr
}

func buildAttributeValue(parsed *parser.File, n *gotreesitter.Node) Expr {
	if n == nil {
		return nil
	}
	if n.Type(parsed.Lang) == "attribute_value" && n.NamedChildCount() == 1 {
		return buildAttributeValue(parsed, n.NamedChild(0))
	}
	switch n.Type(parsed.Lang) {
	case "string_literal":
		return StringExpr{
			Value: strings.Trim(text(parsed, n), `"`),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "number_literal":
		return IntExpr{
			Value: text(parsed, n),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	default:
		return buildExpr(parsed, n)
	}
}

func buildConstDecl(parsed *parser.File, n *gotreesitter.Node) Decl {
	specs := namedDescendantsOfType(parsed, n, "const_spec")
	if len(specs) == 1 && !hasDirectToken(parsed, n, "(") {
		return buildConstSpec(parsed, specs[0])
	}
	group := ConstGroupDecl{Span: spanForNode(parsed.Source.FileID, n)}
	for _, spec := range specs {
		group.Consts = append(group.Consts, buildConstSpec(parsed, spec))
	}
	return group
}

func hasDirectToken(parsed *parser.File, n *gotreesitter.Node, token string) bool {
	if n == nil {
		return false
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.Child(i)
		if child != nil && !child.IsNamed() && text(parsed, child) == token {
			return true
		}
	}
	return false
}

func buildConstSpec(parsed *parser.File, n *gotreesitter.Node) ConstDecl {
	return ConstDecl{
		Name:  text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Type:  buildTypeRef(parsed, n.ChildByFieldName("type", parsed.Lang)),
		Value: buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
		Span:  spanForNode(parsed.Source.FileID, n),
	}
}

func buildEnumDecl(parsed *parser.File, n *gotreesitter.Node) EnumDecl {
	decl := EnumDecl{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Type: buildTypeRef(parsed, n.ChildByFieldName("type", parsed.Lang)),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	for _, child := range namedDescendantsOfType(parsed, n, "enum_value") {
		decl.Values = append(decl.Values, EnumValue{
			Name:  text(parsed, child.ChildByFieldName("name", parsed.Lang)),
			Value: buildExpr(parsed, child.ChildByFieldName("value", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, child),
		})
	}
	return decl
}

func buildCapabilityDecl(parsed *parser.File, n *gotreesitter.Node) CapabilityDecl {
	return CapabilityDecl{
		Name:   text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Value:  strings.Trim(text(parsed, n.ChildByFieldName("value", parsed.Lang)), `"`),
		Danger: text(parsed, n.ChildByFieldName("danger", parsed.Lang)),
		Span:   spanForNode(parsed.Source.FileID, n),
	}
}

func buildBlockStatements(parsed *parser.File, n *gotreesitter.Node) []Stmt {
	if n == nil {
		return nil
	}
	list := firstNamedDescendantOfType(parsed, n, "statement_list")
	if list == nil {
		return nil
	}
	var out []Stmt
	for i := 0; i < int(list.NamedChildCount()); i++ {
		child := list.NamedChild(i)
		if child.Type(parsed.Lang) != "statement" {
			continue
		}
		if stmt := buildStmt(parsed, child); stmt != nil {
			out = append(out, stmt)
		}
	}
	return out
}

func buildStmt(parsed *parser.File, n *gotreesitter.Node) Stmt {
	if n == nil {
		return nil
	}
	if (n.Type(parsed.Lang) == "statement" || n.Type(parsed.Lang) == "if_init_statement" || n.Type(parsed.Lang) == "for_init_statement" || n.Type(parsed.Lang) == "for_post_statement") && n.NamedChildCount() == 1 {
		return buildStmt(parsed, n.NamedChild(0))
	}
	switch n.Type(parsed.Lang) {
	case "var_declaration":
		return VarDeclStmt{
			Name:  text(parsed, n.ChildByFieldName("name", parsed.Lang)),
			Type:  buildTypeRef(parsed, n.ChildByFieldName("type", parsed.Lang)),
			Value: buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "short_var_declaration":
		return ShortVarStmt{
			Name:  text(parsed, n.ChildByFieldName("name", parsed.Lang)),
			Value: buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "assignment_statement":
		return AssignStmt{
			Target: buildExpr(parsed, n.ChildByFieldName("target", parsed.Lang)),
			Value:  buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
			Span:   spanForNode(parsed.Source.FileID, n),
		}
	case "return_statement":
		return ReturnStmt{
			Value: buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "if_statement":
		return IfStmt{
			Init: buildStmt(parsed, n.ChildByFieldName("init", parsed.Lang)),
			Cond: buildExpr(parsed, n.ChildByFieldName("condition", parsed.Lang)),
			Then: buildBlockStatements(parsed, n.ChildByFieldName("consequence", parsed.Lang)),
			Else: buildElseStatements(parsed, n.ChildByFieldName("alternative", parsed.Lang)),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	case "for_statement":
		return ForStmt{
			Init: buildStmt(parsed, n.ChildByFieldName("init", parsed.Lang)),
			Cond: buildExpr(parsed, n.ChildByFieldName("condition", parsed.Lang)),
			Post: buildStmt(parsed, n.ChildByFieldName("post", parsed.Lang)),
			Body: buildBlockStatements(parsed, n.ChildByFieldName("body", parsed.Lang)),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	case "switch_statement":
		return SwitchStmt{
			Value: buildExpr(parsed, n.ChildByFieldName("value", parsed.Lang)),
			Cases: buildSwitchCases(parsed, n),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "expression_statement":
		return ExprStmt{
			Expr: buildExpr(parsed, n.ChildByFieldName("expression", parsed.Lang)),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	case "increment_statement":
		return IncStmt{
			Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
			Op:   operatorText(parsed, n),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	default:
		raw := strings.TrimSpace(text(parsed, n))
		if raw == "" {
			return nil
		}
		return RawStmt{Text: raw, Span: spanForNode(parsed.Source.FileID, n)}
	}
}

func buildSwitchCases(parsed *parser.File, n *gotreesitter.Node) []SwitchCase {
	var out []SwitchCase
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) != "switch_case" {
			continue
		}
		out = append(out, SwitchCase{
			Values:  buildSwitchCaseValues(parsed, child.ChildByFieldName("values", parsed.Lang)),
			Body:    buildBlockStatements(parsed, child),
			Default: child.ChildByFieldName("values", parsed.Lang) == nil,
			Span:    spanForNode(parsed.Source.FileID, child),
		})
	}
	return out
}

func buildSwitchCaseValues(parsed *parser.File, n *gotreesitter.Node) []Expr {
	if n == nil {
		return nil
	}
	var out []Expr
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) != "expression" && child.Type(parsed.Lang) != "condition_expression" {
			continue
		}
		if expr := buildExpr(parsed, child); expr != nil {
			out = append(out, expr)
		}
	}
	return out
}

func buildElseStatements(parsed *parser.File, n *gotreesitter.Node) []Stmt {
	if n == nil {
		return nil
	}
	if n.Type(parsed.Lang) == "if_statement" {
		if stmt := buildStmt(parsed, n); stmt != nil {
			return []Stmt{stmt}
		}
		return nil
	}
	return buildBlockStatements(parsed, n)
}

func buildExpr(parsed *parser.File, n *gotreesitter.Node) Expr {
	if n == nil {
		return nil
	}
	if (n.Type(parsed.Lang) == "expression" || n.Type(parsed.Lang) == "condition_expression") && n.NamedChildCount() == 1 {
		return buildExpr(parsed, n.NamedChild(0))
	}
	switch n.Type(parsed.Lang) {
	case "identifier":
		return IdentExpr{Name: text(parsed, n), Span: spanForNode(parsed.Source.FileID, n)}
	case "string_literal":
		return StringExpr{Value: strings.Trim(text(parsed, n), `"`), Span: spanForNode(parsed.Source.FileID, n)}
	case "number_literal":
		return IntExpr{Value: text(parsed, n), Span: spanForNode(parsed.Source.FileID, n)}
	case "bool_literal":
		return BoolExpr{Value: text(parsed, n) == "true", Span: spanForNode(parsed.Source.FileID, n)}
	case "nil_literal":
		return NilExpr{Span: spanForNode(parsed.Source.FileID, n)}
	case "selector_expression":
		return SelectorExpr{
			Operand: buildExpr(parsed, n.ChildByFieldName("operand", parsed.Lang)),
			Field:   text(parsed, n.ChildByFieldName("field", parsed.Lang)),
			Span:    spanForNode(parsed.Source.FileID, n),
		}
	case "call_expression":
		return CallExpr{
			Func: buildExpr(parsed, n.ChildByFieldName("function", parsed.Lang)),
			Args: buildArgumentList(parsed, n.ChildByFieldName("arguments", parsed.Lang)),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	case "struct_literal":
		return StructLiteralExpr{
			Type:   buildTypeRef(parsed, n.ChildByFieldName("type", parsed.Lang)),
			Fields: buildStructLiteralFields(parsed, n),
			Span:   spanForNode(parsed.Source.FileID, n),
		}
	case "unary_expression", "condition_unary_expression":
		return UnaryExpr{
			Op:   operatorText(parsed, n),
			Expr: buildExpr(parsed, n.ChildByFieldName("operand", parsed.Lang)),
			Span: spanForNode(parsed.Source.FileID, n),
		}
	case "binary_expression", "condition_binary_expression":
		return BinaryExpr{
			Left:  buildExpr(parsed, n.ChildByFieldName("left", parsed.Lang)),
			Op:    operatorText(parsed, n),
			Right: buildExpr(parsed, n.ChildByFieldName("right", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, n),
		}
	case "parenthesized_expression", "condition_parenthesized_expression":
		return buildExpr(parsed, n.ChildByFieldName("expression", parsed.Lang))
	default:
		raw := strings.TrimSpace(text(parsed, n))
		if raw == "" {
			return nil
		}
		return RawExpr{Text: raw, Span: spanForNode(parsed.Source.FileID, n)}
	}
}

func buildStructLiteralFields(parsed *parser.File, n *gotreesitter.Node) []StructLiteralField {
	var out []StructLiteralField
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) != "literal_field" {
			continue
		}
		out = append(out, StructLiteralField{
			Name:  text(parsed, child.ChildByFieldName("name", parsed.Lang)),
			Value: buildExpr(parsed, child.ChildByFieldName("value", parsed.Lang)),
			Span:  spanForNode(parsed.Source.FileID, child),
		})
	}
	return out
}

func buildArgumentList(parsed *parser.File, n *gotreesitter.Node) []Expr {
	if n == nil {
		return nil
	}
	var out []Expr
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type(parsed.Lang) != "expression" {
			continue
		}
		if expr := buildExpr(parsed, child); expr != nil {
			out = append(out, expr)
		}
	}
	return out
}

func operatorText(parsed *parser.File, n *gotreesitter.Node) string {
	if op := n.ChildByFieldName("operator", parsed.Lang); op != nil {
		return text(parsed, op)
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.Child(i)
		if child == nil || child.IsNamed() {
			continue
		}
		switch tok := text(parsed, child); tok {
		case "==", "!=", "<=", ">=", "<", ">", "&&", "||",
			"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
			"!", "++", "--":
			return tok
		}
	}
	return ""
}

func buildTypeRef(parsed *parser.File, n *gotreesitter.Node) TypeRef {
	if n == nil {
		return TypeRef{}
	}
	if n.Type(parsed.Lang) == "type_ref" && n.NamedChildCount() == 1 {
		return buildTypeRef(parsed, n.NamedChild(0))
	}
	ref := TypeRef{
		Name: text(parsed, n),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	switch n.Type(parsed.Lang) {
	case "identifier", "selector_type":
		ref.Name = text(parsed, n)
	case "array_type":
		elem := buildTypeRef(parsed, n.ChildByFieldName("elem", parsed.Lang))
		ref.Name = ""
		ref.Len = text(parsed, n.ChildByFieldName("len", parsed.Lang))
		ref.Elem = &elem
	case "generic_type":
		ref.Name = text(parsed, n.ChildByFieldName("name", parsed.Lang))
		for i := 0; i < int(n.NamedChildCount()); i++ {
			child := n.NamedChild(i)
			if child.Type(parsed.Lang) == "type_ref" {
				ref.Args = append(ref.Args, buildTypeRef(parsed, child))
			}
		}
	case "pointer_type":
		ref.Ptr = true
		if n.NamedChildCount() > 0 {
			elem := buildTypeRef(parsed, n.NamedChild(0))
			ref.Elem = &elem
			ref.Name = elem.Name
		}
	}
	return ref
}

func text(parsed *parser.File, n *gotreesitter.Node) string {
	return parser.NodeText(n, parsed.Source.Bytes)
}

func spanForNode(file span.FileID, n *gotreesitter.Node) span.Span {
	if n == nil {
		return span.Span{File: file}
	}
	start := n.StartPoint()
	end := n.EndPoint()
	return span.Span{
		File:      file,
		StartByte: int(n.StartByte()),
		EndByte:   int(n.EndByte()),
		Start:     span.Point{Line: int(start.Row) + 1, Column: int(start.Column) + 1},
		End:       span.Point{Line: int(end.Row) + 1, Column: int(end.Column) + 1},
	}
}

func firstNamedDescendantOfType(parsed *parser.File, n *gotreesitter.Node, typ string) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	if n.IsNamed() && n.Type(parsed.Lang) == typ {
		return n
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if found := firstNamedDescendantOfType(parsed, n.NamedChild(i), typ); found != nil {
			return found
		}
	}
	return nil
}

func namedDescendantsOfType(parsed *parser.File, n *gotreesitter.Node, typ string) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	var out []*gotreesitter.Node
	var walk func(*gotreesitter.Node)
	walk = func(node *gotreesitter.Node) {
		if node == nil {
			return
		}
		if node.IsNamed() && node.Type(parsed.Lang) == typ {
			out = append(out, node)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(n)
	return out
}
