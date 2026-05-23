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

func buildTypeDecl(parsed *parser.File, n *gotreesitter.Node) TypeDecl {
	decl := TypeDecl{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Span: spanForNode(parsed.Source.FileID, n),
	}
	if typ := n.ChildByFieldName("type", parsed.Lang); typ != nil {
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
		for _, child := range namedDescendantsOfType(parsed, body, "raw_statement") {
			raw := strings.TrimSpace(text(parsed, child))
			if raw == "" {
				continue
			}
			decl.Body = append(decl.Body, RawStmt{
				Text: raw,
				Span: spanForNode(parsed.Source.FileID, child),
			})
		}
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
		attr.Args = append(attr.Args, StringExpr{
			Value: strings.Trim(text(parsed, value), `"`),
			Span:  spanForNode(parsed.Source.FileID, value),
		})
	}
	return attr
}

func buildConstDecl(parsed *parser.File, n *gotreesitter.Node) ConstDecl {
	value := n.ChildByFieldName("value", parsed.Lang)
	return ConstDecl{
		Name: text(parsed, n.ChildByFieldName("name", parsed.Lang)),
		Value: RawExpr{
			Text: strings.TrimSpace(text(parsed, value)),
			Span: spanForNode(parsed.Source.FileID, value),
		},
		Span: spanForNode(parsed.Source.FileID, n),
	}
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
