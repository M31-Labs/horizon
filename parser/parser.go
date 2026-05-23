package parser

import (
	"fmt"
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"m31labs.dev/horizon/grammar"
)

type File struct {
	Source  SourceFile
	Tree    *gotreesitter.Tree
	Lang    *gotreesitter.Language
	Package string
}

func ParsePath(path string) (*File, error) {
	source, err := ReadSource(path)
	if err != nil {
		return nil, err
	}
	return ParseSource(source)
}

func ParseSource(source SourceFile) (*File, error) {
	lang, err := grammar.Language()
	if err != nil {
		return nil, fmt.Errorf("load horizon grammar: %w", err)
	}
	p := gotreesitter.NewParser(lang)
	tree, err := p.Parse(source.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", source.Path, err)
	}
	root := tree.RootNode()
	if tree.ParseStoppedEarly() {
		return nil, &ParseError{Path: source.Path, Line: 1, Column: 1, Message: "parse stopped before consuming the source"}
	}
	if root.HasError() {
		return nil, parseProblem(source.Path, root, source.Bytes, lang)
	}
	return &File{
		Source:  source,
		Tree:    tree,
		Lang:    lang,
		Package: packageName(root, source.Bytes, lang),
	}, nil
}

func packageName(root *gotreesitter.Node, source []byte, lang *gotreesitter.Language) string {
	if pkg := firstNamedDescendant(root, lang, "package_clause"); pkg != nil {
		return NodeText(pkg.ChildByFieldName("name", lang), source)
	}
	return ""
}

func parseProblem(path string, root *gotreesitter.Node, source []byte, lang *gotreesitter.Language) error {
	node := firstProblem(root)
	if node == nil {
		return &ParseError{Path: path, Line: 1, Column: 1, Message: "parse error"}
	}
	point := node.StartPoint()
	return &ParseError{
		Path:    path,
		Line:    int(point.Row) + 1,
		Column:  int(point.Column) + 1,
		Message: parseProblemMessage(node, source, lang),
	}
}

func firstProblem(node *gotreesitter.Node) *gotreesitter.Node {
	if node == nil {
		return nil
	}
	if node.IsMissing() || node.IsError() {
		return node
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if found := firstProblem(node.Child(i)); found != nil {
			return found
		}
	}
	return nil
}

func parseProblemMessage(node *gotreesitter.Node, source []byte, lang *gotreesitter.Language) string {
	if node.IsMissing() {
		if typ := node.Type(lang); typ != "" {
			return "parse error: missing " + typ
		}
		return "parse error: missing token"
	}
	snippet := strings.TrimSpace(NodeText(node, source))
	snippet = strings.Join(strings.Fields(snippet), " ")
	if len(snippet) > 40 {
		snippet = snippet[:37] + "..."
	}
	if snippet != "" {
		return fmt.Sprintf("parse error near %q", snippet)
	}
	return "parse error"
}

func firstNamedDescendant(node *gotreesitter.Node, lang *gotreesitter.Language, typ string) *gotreesitter.Node {
	if node == nil {
		return nil
	}
	if node.IsNamed() && node.Type(lang) == typ {
		return node
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if found := firstNamedDescendant(node.NamedChild(i), lang, typ); found != nil {
			return found
		}
	}
	return nil
}
