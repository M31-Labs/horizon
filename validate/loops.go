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
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
			diags = append(diags, validateTypedLoops(fn)...)
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

func validateTypedLoops(fn ir.Function) []diag.Diagnostic {
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
				case !isBoundedForClause(stmt):
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2202",
						Severity: diag.SeverityError,
						Message:  "for loop must use a simple constant upper bound",
						Primary:  stmt.Span,
						Suggest:  "use `for i := 0; i < N; i++` with a numeric literal bound",
					})
				}
				walk(stmt.Body)
			case "if":
				walk(stmt.Then)
			}
		}
	}
	walk(functionStatements(fn))
	return diags
}

func isBoundedForClause(stmt ir.Statement) bool {
	if stmt.Kind != "for" || stmt.Init == nil || stmt.Cond == nil || stmt.Post == nil {
		return false
	}
	if stmt.Init.Kind != "short_var" || stmt.Init.Name == "" || stmt.Init.Value == nil || stmt.Init.Value.Kind != "int" {
		return false
	}
	if stmt.Cond.Kind != "binary" || stmt.Cond.Op != "<" || stmt.Cond.Left == nil || stmt.Cond.Right == nil {
		return false
	}
	if stmt.Cond.Left.Kind != "ident" || stmt.Cond.Left.Name != stmt.Init.Name || stmt.Cond.Right.Kind != "int" {
		return false
	}
	return stmt.Post.Kind == "inc" && stmt.Post.Name == stmt.Init.Name && stmt.Post.Op == "++"
}
