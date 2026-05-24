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
	if offset, ok := firstTrailingSourceByte(source.Bytes, int(root.EndByte())); ok {
		line, column := pointForOffset(source.Bytes, offset)
		end := snippetEnd(source.Bytes, offset)
		endLine, endColumn := pointForOffset(source.Bytes, end)
		return nil, &ParseError{
			Path:      source.Path,
			Line:      line,
			Column:    column,
			EndLine:   endLine,
			EndColumn: endColumn,
			StartByte: offset,
			EndByte:   end,
			Message:   trailingSourceMessage(source.Bytes, offset),
		}
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
	end := node.EndPoint()
	return &ParseError{
		Path:      path,
		Line:      int(point.Row) + 1,
		Column:    int(point.Column) + 1,
		EndLine:   int(end.Row) + 1,
		EndColumn: int(end.Column) + 1,
		StartByte: int(node.StartByte()),
		EndByte:   int(node.EndByte()),
		Message:   parseProblemMessage(node, source, lang),
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

func firstTrailingSourceByte(source []byte, start int) (int, bool) {
	for i := start; i < len(source); {
		switch source[i] {
		case ' ', '\t', '\f', '\r', '\n':
			i++
			continue
		case '/':
			if i+1 < len(source) && source[i+1] == '/' {
				i += 2
				for i < len(source) && source[i] != '\n' && source[i] != '\r' {
					i++
				}
				continue
			}
		}
		return i, true
	}
	return 0, false
}

func pointForOffset(source []byte, offset int) (int, int) {
	line, column := 1, 1
	if offset > len(source) {
		offset = len(source)
	}
	for i := 0; i < offset; i++ {
		if source[i] == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}
	return line, column
}

func snippetEnd(source []byte, start int) int {
	end := start
	for end < len(source) && source[end] != '\n' && source[end] != '\r' {
		end++
	}
	if end == start && end < len(source) {
		end++
	}
	return end
}

func trailingSourceMessage(source []byte, offset int) string {
	snippet := strings.TrimSpace(string(source[offset:snippetEnd(source, offset)]))
	snippet = strings.Join(strings.Fields(snippet), " ")
	if len(snippet) > 40 {
		snippet = snippet[:37] + "..."
	}
	if snippet != "" {
		return fmt.Sprintf("parse error near %q", snippet)
	}
	return "parse error: unexpected trailing source"
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
