package validate

import (
	"fmt"
	"regexp"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

var boundedForRE = regexp.MustCompile(`\bfor\b.*<\s*[0-9]+`)

func ValidateLoops(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	loopBounds := integerLoopBounds(program.Constants)
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
			diags = append(diags, validateTypedLoops(fn, loopBounds)...)
			continue
		}
		for _, line := range bodyLines(fn) {
			line = strings.TrimSpace(line)
			switch {
			case line == "for {" || strings.HasPrefix(line, "for {"):
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2200",
					Severity: diag.SeverityError,
					Message:  "unbounded for loop is not allowed in v0",
					Primary:  fn.Span,
					Suggest:  "use a for loop with a constant upper bound",
				})
			case strings.HasPrefix(line, "while "):
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2201",
					Severity: diag.SeverityError,
					Message:  "while loops are not allowed in v0",
					Primary:  fn.Span,
				})
			case strings.HasPrefix(line, "for ") && !boundedForRE.MatchString(line):
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2202",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("loop %q does not have a constant upper bound", line),
					Primary:  fn.Span,
				})
			}
		}
	}
	return diags
}

func validateTypedLoops(fn ir.Function, loopBounds map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	var walk func([]ir.Statement)
	walk = func(stmts []ir.Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "for":
				switch {
				case stmt.Init == nil && (stmt.Cond == nil || stmt.Cond.Kind == "") && stmt.Post == nil:
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2200",
						Severity: diag.SeverityError,
						Message:  "unbounded for loop is not allowed in v0",
						Primary:  stmt.Span,
						Suggest:  "use a for loop with a constant upper bound",
					})
				case !isBoundedForClause(stmt, loopBounds):
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2202",
						Severity: diag.SeverityError,
						Message:  "for loop must use a simple constant upper bound",
						Primary:  stmt.Span,
						Suggest:  "use `for i := 0; i < N; i++` with a numeric literal or integer const bound",
					})
				}
				walk(stmt.Body)
			case "if":
				if stmt.Init != nil {
					walk([]ir.Statement{*stmt.Init})
				}
				walk(stmt.Then)
				walk(stmt.Else)
			}
		}
	}
	walk(functionStatements(fn))
	return diags
}

func isBoundedForClause(stmt ir.Statement, loopBounds map[string]bool) bool {
	if stmt.Kind != "for" || stmt.Init == nil || stmt.Cond == nil || stmt.Post == nil {
		return false
	}
	if stmt.Init.Kind != "short_var" || stmt.Init.Name == "" || stmt.Init.Value == nil || stmt.Init.Value.Kind != "int" {
		return false
	}
	if stmt.Cond.Kind != "binary" || stmt.Cond.Op != "<" || stmt.Cond.Left == nil || stmt.Cond.Right == nil {
		return false
	}
	if stmt.Cond.Left.Kind != "ident" || stmt.Cond.Left.Name != stmt.Init.Name || !isConstantLoopBound(stmt.Cond.Right, loopBounds) {
		return false
	}
	return stmt.Post.Kind == "inc" && stmt.Post.Name == stmt.Init.Name && stmt.Post.Op == "++"
}

func isConstantLoopBound(expr *ir.Expr, loopBounds map[string]bool) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case "int":
		return true
	case "ident":
		return loopBounds[expr.Name]
	default:
		return false
	}
}

func integerLoopBounds(constants []ir.Const) map[string]bool {
	out := map[string]bool{}
	for _, c := range constants {
		if c.Name == "" || c.Value.Kind != "int" {
			continue
		}
		if c.Type.Name == "" && c.Type.Elem == nil && !c.Type.Ptr && len(c.Type.Args) == 0 {
			out[c.Name] = true
			continue
		}
		if isIntegerConstType(c.Type) {
			out[c.Name] = true
		}
	}
	return out
}

func isIntegerConstType(typ ir.Type) bool {
	if typ.Ptr || typ.Elem != nil || typ.Len != "" || len(typ.Args) > 0 {
		return false
	}
	switch typ.Name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64":
		return true
	default:
		return false
	}
}
