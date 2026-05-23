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
				if stmt.Cond == nil || stmt.Cond.Kind == "" {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2200",
						Severity: diag.SeverityError,
						Message:  "unbounded for loop is not allowed in v0",
						Primary:  stmt.Span,
						Suggest:  "use a for loop with a constant upper bound",
					})
				} else {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2202",
						Severity: diag.SeverityError,
						Message:  "condition-only for loops are not allowed in v0",
						Primary:  stmt.Span,
						Suggest:  "use `for i := 0; i < N; i++` once bounded for clauses are enabled",
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
