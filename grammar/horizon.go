package grammar

import (
	"sync"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammargen"
)

var (
	langOnce sync.Once
	lang     *gotreesitter.Language
	langErr  error
)

func Language() (*gotreesitter.Language, error) {
	langOnce.Do(func() {
		lang, langErr = grammargen.GenerateLanguage(HorizonGrammar())
	})
	return lang, langErr
}

func HorizonGrammar() *grammargen.Grammar {
	g := grammargen.NewGrammar("horizon")
	g.SetWord("identifier")
	g.SetExtras(grammargen.Pat(`\s`), grammargen.Sym("line_comment"))

	g.Define("source_file", grammargen.Repeat(grammargen.Sym("_item")))
	g.Define("_item", grammargen.Choice(
		grammargen.Sym("package_clause"),
		grammargen.Sym("import_declaration"),
		grammargen.Sym("type_declaration"),
		grammargen.Sym("const_declaration"),
		grammargen.Sym("map_declaration"),
		grammargen.Sym("function_declaration"),
	))

	g.Define("package_clause", grammargen.Seq(
		grammargen.Str("package"),
		grammargen.Field("name", grammargen.Sym("identifier")),
	))

	g.Define("import_declaration", grammargen.Seq(
		grammargen.Str("import"),
		grammargen.Optional(grammargen.Field("alias", grammargen.Sym("identifier"))),
		grammargen.Field("path", grammargen.Sym("string_literal")),
	))

	g.Define("type_declaration", grammargen.Seq(
		grammargen.Str("type"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("struct_type")),
	))

	g.Define("struct_type", grammargen.Seq(
		grammargen.Str("struct"),
		grammargen.Str("{"),
		grammargen.Repeat(grammargen.Sym("field_declaration")),
		grammargen.Str("}"),
	))

	g.Define("field_declaration", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))

	g.Define("const_declaration", grammargen.Seq(
		grammargen.Str("const"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("="),
		grammargen.Field("value", grammargen.Sym("raw_expr")),
	))

	g.Define("map_declaration", grammargen.Seq(
		grammargen.Str("map"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))

	g.Define("function_declaration", grammargen.Seq(
		grammargen.Repeat(grammargen.Sym("attribute")),
		grammargen.Str("func"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("("),
		grammargen.Optional(grammargen.Sym("parameter_list")),
		grammargen.Str(")"),
		grammargen.Optional(grammargen.Field("return", grammargen.Sym("type_ref"))),
		grammargen.Field("body", grammargen.Sym("block")),
	))

	g.Define("attribute", grammargen.Seq(
		grammargen.Str("@"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("("),
		grammargen.Optional(grammargen.Field("value", grammargen.Sym("string_literal"))),
		grammargen.Str(")"),
	))

	g.Define("parameter_list", grammargen.Seq(
		grammargen.Sym("parameter"),
		grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("parameter"))),
	))

	g.Define("parameter", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))

	g.Define("type_ref", grammargen.Choice(
		grammargen.Sym("array_type"),
		grammargen.Sym("generic_type"),
		grammargen.Sym("selector_type"),
		grammargen.Sym("pointer_type"),
		grammargen.Sym("identifier"),
	))

	g.Define("array_type", grammargen.Seq(
		grammargen.Str("["),
		grammargen.Field("len", grammargen.Sym("number_literal")),
		grammargen.Str("]"),
		grammargen.Field("elem", grammargen.Sym("type_ref")),
	))

	g.Define("generic_type", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("["),
		grammargen.Sym("type_ref"),
		grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("type_ref"))),
		grammargen.Str("]"),
	))

	g.Define("selector_type", grammargen.Seq(
		grammargen.Sym("identifier"),
		grammargen.Str("."),
		grammargen.Sym("identifier"),
	))

	g.Define("pointer_type", grammargen.Seq(
		grammargen.Str("*"),
		grammargen.Sym("type_ref"),
	))

	g.Define("block", grammargen.Seq(
		grammargen.Str("{"),
		grammargen.Repeat(grammargen.Choice(
			grammargen.Sym("block"),
			grammargen.Token(grammargen.Pat(`[^{}]+`)),
		)),
		grammargen.Str("}"),
	))

	g.Define("raw_expr", grammargen.Token(grammargen.Pat(`[^\n\r]+`)))
	g.Define("identifier", grammargen.Token(grammargen.Pat(`[A-Za-z_][A-Za-z0-9_]*`)))
	g.Define("number_literal", grammargen.Token(grammargen.Pat(`[0-9]+`)))
	g.Define("string_literal", grammargen.Token(grammargen.Seq(
		grammargen.Str(`"`),
		grammargen.Pat(`[^"]*`),
		grammargen.Str(`"`),
	)))
	g.Define("line_comment", grammargen.Token(grammargen.Pat(`//[^\n]*`)))

	return g
}
