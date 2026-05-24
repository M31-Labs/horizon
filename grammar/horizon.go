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

	defineSourceFile(g)
	defineDeclarations(g)
	defineTypes(g)
	defineFunctions(g)
	defineStatements(g)
	defineExpressions(g)
	defineTokens(g)

	return g
}

func binaryOp(prec int, op string) *grammargen.Rule {
	return binaryOps(prec, op)
}

func binaryOps(prec int, ops ...string) *grammargen.Rule {
	return binaryOpsFor(prec, "expression", ops...)
}

func conditionBinaryOp(prec int, op string) *grammargen.Rule {
	return conditionBinaryOps(prec, op)
}

func conditionBinaryOps(prec int, ops ...string) *grammargen.Rule {
	return binaryOpsFor(prec, "condition_expression", ops...)
}

func binaryOpsFor(prec int, operand string, ops ...string) *grammargen.Rule {
	choices := make([]*grammargen.Rule, 0, len(ops))
	for _, op := range ops {
		choices = append(choices, grammargen.Str(op))
	}
	return grammargen.PrecLeft(prec, grammargen.Seq(
		grammargen.Field("left", grammargen.Sym(operand)),
		grammargen.Field("operator", grammargen.Choice(choices...)),
		grammargen.Field("right", grammargen.Sym(operand)),
	))
}
