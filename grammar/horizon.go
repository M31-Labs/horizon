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
	g.SetExtras(grammargen.Pat(`[ \t\f]+`), grammargen.Sym("line_comment"))

	g.Define("source_file", grammargen.Seq(
		grammargen.Repeat(grammargen.Choice(
			grammargen.Seq(
				grammargen.Sym("_item"),
				grammargen.Repeat1(grammargen.Sym("_terminator")),
			),
			grammargen.Sym("_terminator"),
		)),
		grammargen.Choice(
			grammargen.Sym("_item"),
			grammargen.Blank(),
		),
	))
	g.Define("_item", grammargen.Choice(
		grammargen.Sym("package_clause"),
		grammargen.Sym("import_declaration"),
		grammargen.Sym("type_declaration"),
		grammargen.Sym("const_declaration"),
		grammargen.Sym("map_declaration"),
		grammargen.Sym("function_declaration"),
	))
	g.Define("_terminator", grammargen.Choice(
		grammargen.Pat(`\r?\n`),
		grammargen.Str(";"),
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
		grammargen.Repeat(grammargen.Sym("_terminator")),
		grammargen.Repeat(grammargen.Seq(
			grammargen.Sym("field_declaration"),
			grammargen.Repeat1(grammargen.Sym("_terminator")),
		)),
		grammargen.Optional(grammargen.Sym("field_declaration")),
		grammargen.Repeat(grammargen.Sym("_terminator")),
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
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("map_declaration", grammargen.Seq(
		grammargen.Str("map"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))

	g.Define("function_declaration", grammargen.Seq(
		grammargen.Repeat(grammargen.Seq(
			grammargen.Sym("attribute"),
			grammargen.Repeat(grammargen.Sym("_terminator")),
		)),
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
		grammargen.Optional(grammargen.Seq(
			grammargen.Str("("),
			grammargen.Optional(grammargen.Field("value", grammargen.Sym("string_literal"))),
			grammargen.Str(")"),
		)),
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
		grammargen.Sym("statement_list"),
		grammargen.Str("}"),
	))

	g.Define("statement_list", grammargen.Seq(
		grammargen.Repeat(grammargen.Choice(
			grammargen.Sym("_terminator"),
			grammargen.Seq(grammargen.Sym("statement"), grammargen.Repeat1(grammargen.Sym("_terminator"))),
		)),
		grammargen.Optional(grammargen.Sym("statement")),
	))

	g.Define("statement", grammargen.Choice(
		grammargen.Sym("short_var_declaration"),
		grammargen.Sym("assignment_statement"),
		grammargen.Sym("return_statement"),
		grammargen.Sym("if_statement"),
		grammargen.Sym("for_statement"),
		grammargen.Sym("expression_statement"),
	))

	g.Define("short_var_declaration", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str(":="),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("assignment_statement", grammargen.Seq(
		grammargen.Field("target", grammargen.Sym("expression")),
		grammargen.Str("="),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("return_statement", grammargen.Seq(
		grammargen.Str("return"),
		grammargen.Optional(grammargen.Field("value", grammargen.Sym("expression"))),
	))

	g.Define("if_statement", grammargen.Seq(
		grammargen.Str("if"),
		grammargen.Field("condition", grammargen.Sym("expression")),
		grammargen.Field("consequence", grammargen.Sym("block")),
		grammargen.Optional(grammargen.Seq(
			grammargen.Str("else"),
			grammargen.Field("alternative", grammargen.Choice(
				grammargen.Sym("block"),
				grammargen.Sym("if_statement"),
			)),
		)),
	))

	g.Define("for_statement", grammargen.Seq(
		grammargen.Str("for"),
		grammargen.Choice(
			grammargen.Field("body", grammargen.Sym("block")),
			grammargen.Seq(
				grammargen.Field("init", grammargen.Sym("for_init_statement")),
				grammargen.Str(";"),
				grammargen.Field("condition", grammargen.Sym("expression")),
				grammargen.Str(";"),
				grammargen.Field("post", grammargen.Sym("for_post_statement")),
				grammargen.Field("body", grammargen.Sym("block")),
			),
			grammargen.Seq(
				grammargen.Field("condition", grammargen.Sym("expression")),
				grammargen.Field("body", grammargen.Sym("block")),
			),
		),
	))

	g.Define("for_init_statement", grammargen.Sym("short_var_declaration"))
	g.Define("for_post_statement", grammargen.Sym("increment_statement"))

	g.Define("increment_statement", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("operator", grammargen.Choice(
			grammargen.Str("++"),
			grammargen.Str("--"),
		)),
	))

	g.Define("expression_statement", grammargen.Field("expression", grammargen.Sym("expression")))

	g.Define("expression", grammargen.Choice(
		grammargen.Sym("binary_expression"),
		grammargen.Sym("parenthesized_expression"),
		grammargen.Sym("struct_literal"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	g.Define("binary_expression", grammargen.Choice(
		binaryOp(1, "||"),
		binaryOp(2, "&&"),
		binaryOps(3, "==", "!=", "<=", ">=", "<", ">"),
		binaryOp(4, "|"),
		binaryOp(5, "^"),
		binaryOp(6, "&"),
		binaryOps(7, "<<", ">>"),
		binaryOps(8, "+", "-"),
		binaryOps(9, "*", "/", "%"),
	))

	g.Define("_simple_expression", grammargen.Choice(
		grammargen.Sym("parenthesized_expression"),
		grammargen.Sym("struct_literal"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	g.Define("parenthesized_expression", grammargen.Seq(
		grammargen.Str("("),
		grammargen.Field("expression", grammargen.Sym("expression")),
		grammargen.Str(")"),
	))

	g.Define("struct_literal", grammargen.Prec(2, grammargen.Seq(
		grammargen.Field("type", grammargen.Sym("identifier")),
		grammargen.Str("{"),
		grammargen.Optional(grammargen.Seq(
			grammargen.Sym("literal_field"),
			grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("literal_field"))),
			grammargen.Optional(grammargen.Str(",")),
		)),
		grammargen.Str("}"),
	)))

	g.Define("literal_field", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str(":"),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("call_expression", grammargen.Prec(3, grammargen.Seq(
		grammargen.Field("function", grammargen.Choice(
			grammargen.Sym("selector_expression"),
			grammargen.Sym("identifier"),
		)),
		grammargen.Field("arguments", grammargen.Sym("argument_list")),
	)))

	g.Define("argument_list", grammargen.Seq(
		grammargen.Str("("),
		grammargen.Optional(grammargen.Seq(
			grammargen.Sym("expression"),
			grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("expression"))),
		)),
		grammargen.Str(")"),
	))

	g.Define("selector_expression", grammargen.Prec(4, grammargen.Seq(
		grammargen.Field("operand", grammargen.Choice(
			grammargen.Sym("selector_expression"),
			grammargen.Sym("identifier"),
		)),
		grammargen.Str("."),
		grammargen.Field("field", grammargen.Sym("identifier")),
	)))

	g.Define("unary_expression", grammargen.Prec(5, grammargen.Seq(
		grammargen.Field("operator", grammargen.Choice(
			grammargen.Str("&"),
			grammargen.Str("*"),
			grammargen.Str("!"),
		)),
		grammargen.Field("operand", grammargen.Sym("_simple_expression")),
	)))

	g.Define("raw_expr", grammargen.Token(grammargen.Pat(`[^\n\r]+`)))
	g.Define("nil_literal", grammargen.Str("nil"))
	g.Define("identifier", grammargen.Token(grammargen.Pat(`[A-Za-z_][A-Za-z0-9_]*`)))
	g.Define("number_literal", grammargen.Token(grammargen.Pat(`0[xX][0-9a-fA-F]+|[0-9]+`)))
	g.Define("string_literal", grammargen.Token(grammargen.Seq(
		grammargen.Str(`"`),
		grammargen.Pat(`[^"]*`),
		grammargen.Str(`"`),
	)))
	g.Define("line_comment", grammargen.Token(grammargen.Pat(`//[^\n]*`)))

	return g
}

func binaryOp(prec int, op string) *grammargen.Rule {
	return binaryOps(prec, op)
}

func binaryOps(prec int, ops ...string) *grammargen.Rule {
	choices := make([]*grammargen.Rule, 0, len(ops))
	for _, op := range ops {
		choices = append(choices, grammargen.Str(op))
	}
	return grammargen.PrecLeft(prec, grammargen.Seq(
		grammargen.Field("left", grammargen.Sym("expression")),
		grammargen.Field("operator", grammargen.Choice(choices...)),
		grammargen.Field("right", grammargen.Sym("expression")),
	))
}
