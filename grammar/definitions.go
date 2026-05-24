package grammar

import "github.com/odvcencio/gotreesitter/grammargen"

func defineSourceFile(g *grammargen.Grammar) {
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
		grammargen.Sym("enum_declaration"),
		grammargen.Sym("capability_declaration"),
		grammargen.Sym("map_declaration"),
		grammargen.Sym("function_declaration"),
	))
	g.Define("_terminator", grammargen.Choice(
		grammargen.Pat(`\r?\n`),
		grammargen.Str(";"),
	))
}

func defineDeclarations(g *grammargen.Grammar) {
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

	g.Define("const_declaration", grammargen.Seq(
		grammargen.Str("const"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Optional(grammargen.Field("type", grammargen.Sym("type_ref"))),
		grammargen.Str("="),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("enum_declaration", grammargen.Seq(
		grammargen.Str("enum"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
		grammargen.Str("{"),
		grammargen.Repeat(grammargen.Sym("_terminator")),
		grammargen.Repeat(grammargen.Seq(
			grammargen.Sym("enum_value"),
			grammargen.Repeat1(grammargen.Sym("_terminator")),
		)),
		grammargen.Optional(grammargen.Sym("enum_value")),
		grammargen.Repeat(grammargen.Sym("_terminator")),
		grammargen.Str("}"),
	))

	g.Define("enum_value", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("="),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("capability_declaration", grammargen.Seq(
		grammargen.Str("capability"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str("="),
		grammargen.Field("value", grammargen.Sym("string_literal")),
	))

	g.Define("map_declaration", grammargen.Seq(
		grammargen.Repeat(grammargen.Seq(
			grammargen.Sym("attribute"),
			grammargen.Repeat(grammargen.Sym("_terminator")),
		)),
		grammargen.Str("map"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))
}

func defineTypes(g *grammargen.Grammar) {
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
}

func defineFunctions(g *grammargen.Grammar) {
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
			grammargen.Optional(grammargen.Field("value", grammargen.Sym("attribute_value"))),
			grammargen.Str(")"),
		)),
	))

	g.Define("attribute_value", grammargen.Choice(
		grammargen.Sym("string_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	g.Define("parameter_list", grammargen.Seq(
		grammargen.Sym("parameter"),
		grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("parameter"))),
	))

	g.Define("parameter", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
	))
}

func defineStatements(g *grammargen.Grammar) {
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
		grammargen.Sym("var_declaration"),
		grammargen.Sym("short_var_declaration"),
		grammargen.Sym("assignment_statement"),
		grammargen.Sym("return_statement"),
		grammargen.Sym("if_statement"),
		grammargen.Sym("for_statement"),
		grammargen.Sym("switch_statement"),
		grammargen.Sym("expression_statement"),
	))

	g.Define("short_var_declaration", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Str(":="),
		grammargen.Field("value", grammargen.Sym("expression")),
	))

	g.Define("var_declaration", grammargen.Seq(
		grammargen.Str("var"),
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("type", grammargen.Sym("type_ref")),
		grammargen.Str("="),
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
		grammargen.Optional(grammargen.Seq(
			grammargen.Field("init", grammargen.Sym("if_init_statement")),
			grammargen.Str(";"),
		)),
		grammargen.Field("condition", grammargen.Sym("condition_expression")),
		grammargen.Field("consequence", grammargen.Sym("block")),
		grammargen.Optional(grammargen.Seq(
			grammargen.Str("else"),
			grammargen.Field("alternative", grammargen.Choice(
				grammargen.Sym("block"),
				grammargen.Sym("if_statement"),
			)),
		)),
	))

	g.Define("if_init_statement", grammargen.Sym("short_var_declaration"))

	g.Define("for_statement", grammargen.Seq(
		grammargen.Str("for"),
		grammargen.Choice(
			grammargen.Field("body", grammargen.Sym("block")),
			grammargen.Seq(
				grammargen.Field("init", grammargen.Sym("for_init_statement")),
				grammargen.Str(";"),
				grammargen.Field("condition", grammargen.Sym("condition_expression")),
				grammargen.Str(";"),
				grammargen.Field("post", grammargen.Sym("for_post_statement")),
				grammargen.Field("body", grammargen.Sym("block")),
			),
			grammargen.Seq(
				grammargen.Field("condition", grammargen.Sym("condition_expression")),
				grammargen.Field("body", grammargen.Sym("block")),
			),
		),
	))

	g.Define("for_init_statement", grammargen.Choice(
		grammargen.Sym("short_var_declaration"),
		grammargen.Sym("var_declaration"),
	))
	g.Define("for_post_statement", grammargen.Sym("increment_statement"))

	g.Define("increment_statement", grammargen.Seq(
		grammargen.Field("name", grammargen.Sym("identifier")),
		grammargen.Field("operator", grammargen.Choice(
			grammargen.Str("++"),
			grammargen.Str("--"),
		)),
	))

	g.Define("switch_statement", grammargen.Seq(
		grammargen.Str("switch"),
		grammargen.Field("value", grammargen.Sym("condition_expression")),
		grammargen.Str("{"),
		grammargen.Repeat(grammargen.Sym("_terminator")),
		grammargen.Repeat(grammargen.Sym("switch_case")),
		grammargen.Str("}"),
	))

	g.Define("switch_case", grammargen.Choice(
		grammargen.Seq(
			grammargen.Str("case"),
			grammargen.Field("values", grammargen.Sym("switch_case_values")),
			grammargen.Str(":"),
			grammargen.Sym("statement_list"),
		),
		grammargen.Seq(
			grammargen.Str("default"),
			grammargen.Str(":"),
			grammargen.Sym("statement_list"),
		),
	))

	g.Define("switch_case_values", grammargen.Seq(
		grammargen.Sym("condition_expression"),
		grammargen.Repeat(grammargen.Seq(grammargen.Str(","), grammargen.Sym("condition_expression"))),
		grammargen.Optional(grammargen.Str(",")),
	))

	g.Define("expression_statement", grammargen.Field("expression", grammargen.Sym("expression")))
}

func defineExpressions(g *grammargen.Grammar) {
	g.Define("expression", grammargen.Choice(
		grammargen.Sym("binary_expression"),
		grammargen.Sym("parenthesized_expression"),
		grammargen.Sym("struct_literal"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("bool_literal"),
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

	g.Define("condition_expression", grammargen.Choice(
		grammargen.Sym("condition_binary_expression"),
		grammargen.Sym("condition_parenthesized_expression"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("condition_unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("bool_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	g.Define("condition_binary_expression", grammargen.Choice(
		conditionBinaryOp(1, "||"),
		conditionBinaryOp(2, "&&"),
		conditionBinaryOps(3, "==", "!=", "<=", ">=", "<", ">"),
		conditionBinaryOp(4, "|"),
		conditionBinaryOp(5, "^"),
		conditionBinaryOp(6, "&"),
		conditionBinaryOps(7, "<<", ">>"),
		conditionBinaryOps(8, "+", "-"),
		conditionBinaryOps(9, "*", "/", "%"),
	))

	g.Define("_simple_expression", grammargen.Choice(
		grammargen.Sym("parenthesized_expression"),
		grammargen.Sym("struct_literal"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("bool_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	g.Define("_simple_condition_expression", grammargen.Choice(
		grammargen.Sym("condition_parenthesized_expression"),
		grammargen.Sym("call_expression"),
		grammargen.Sym("condition_unary_expression"),
		grammargen.Sym("selector_expression"),
		grammargen.Sym("nil_literal"),
		grammargen.Sym("bool_literal"),
		grammargen.Sym("number_literal"),
		grammargen.Sym("identifier"),
	))

	defineExpressionAtoms(g)
}

func defineExpressionAtoms(g *grammargen.Grammar) {
	g.Define("parenthesized_expression", grammargen.Seq(
		grammargen.Str("("),
		grammargen.Field("expression", grammargen.Sym("expression")),
		grammargen.Str(")"),
	))

	g.Define("condition_parenthesized_expression", grammargen.Seq(
		grammargen.Str("("),
		grammargen.Field("expression", grammargen.Sym("condition_expression")),
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
			grammargen.Str("-"),
		)),
		grammargen.Field("operand", grammargen.Sym("_simple_expression")),
	)))

	g.Define("condition_unary_expression", grammargen.Prec(5, grammargen.Seq(
		grammargen.Field("operator", grammargen.Choice(
			grammargen.Str("&"),
			grammargen.Str("*"),
			grammargen.Str("!"),
			grammargen.Str("-"),
		)),
		grammargen.Field("operand", grammargen.Sym("_simple_condition_expression")),
	)))
}

func defineTokens(g *grammargen.Grammar) {
	g.Define("raw_expr", grammargen.Token(grammargen.Pat(`[^\n\r]+`)))
	g.Define("nil_literal", grammargen.Str("nil"))
	g.Define("bool_literal", grammargen.Choice(
		grammargen.Str("true"),
		grammargen.Str("false"),
	))
	g.Define("identifier", grammargen.Token(grammargen.Pat(`[A-Za-z_][A-Za-z0-9_]*`)))
	g.Define("number_literal", grammargen.Token(grammargen.Pat(`0[xX][0-9a-fA-F]+|[0-9]+`)))
	g.Define("string_literal", grammargen.Token(grammargen.Seq(
		grammargen.Str(`"`),
		grammargen.Pat(`[^"]*`),
		grammargen.Str(`"`),
	)))
	g.Define("line_comment", grammargen.Token(grammargen.Pat(`//[^\n]*`)))
}
