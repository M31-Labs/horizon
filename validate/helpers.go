package validate

import (
	"fmt"
	"regexp"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

var helperCallRE = regexp.MustCompile(`\bbpf\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

func ValidateHelpers(program ir.Program) []diag.Diagnostic {
	allowed := map[string]bool{
		"current_pid":  true,
		"current_ppid": true,
		"current_uid":  true,
		"current_comm": true,
	}
	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
			diags = append(diags, validateTypedHelpers(fn, allowed)...)
			continue
		}
		for _, line := range bodyLines(fn) {
			for _, match := range helperCallRE.FindAllStringSubmatch(line, -1) {
				helper := match[1]
				if allowed[helper] && fn.Section.Kind == ir.ProgramTracepoint {
					continue
				}
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2300",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("helper bpf.%s is not available for %s programs", helper, fn.Section.Kind),
					Primary:  fn.Span,
				})
			}
		}
	}
	return diags
}

func validateTypedHelpers(fn ir.Function, allowed map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	walkStatements(functionStatements(fn), func(expr *ir.Expr) {
		if expr == nil || expr.Kind != "call" {
			return
		}
		name := irQualifiedName(expr.Func)
		if name == "" || len(name) <= len("bpf.") || name[:len("bpf.")] != "bpf." {
			return
		}
		helper := name[len("bpf."):]
		if allowed[helper] && fn.Section.Kind == ir.ProgramTracepoint {
			return
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN2300",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("helper bpf.%s is not available for %s programs", helper, fn.Section.Kind),
			Primary:  expr.Span,
		})
	})
	return diags
}

func walkStatements(stmts []ir.Statement, visit func(*ir.Expr)) {
	for _, stmt := range stmts {
		switch stmt.Kind {
		case "short_var":
			walkExpr(stmt.Value, visit)
		case "assign":
			walkExpr(stmt.Target, visit)
			walkExpr(stmt.Value, visit)
		case "expr":
			walkExpr(stmt.Expr, visit)
		case "return":
			walkExpr(stmt.Value, visit)
		case "if":
			walkExpr(stmt.Cond, visit)
			walkStatements(stmt.Then, visit)
		case "for":
			walkExpr(stmt.Cond, visit)
			walkStatements(stmt.Body, visit)
		}
	}
}

func walkExpr(expr *ir.Expr, visit func(*ir.Expr)) {
	if expr == nil {
		return
	}
	visit(expr)
	walkExpr(expr.Operand, visit)
	walkExpr(expr.Left, visit)
	walkExpr(expr.Right, visit)
	walkExpr(expr.Func, visit)
	for i := range expr.Args {
		walkExpr(&expr.Args[i], visit)
	}
}

func irQualifiedName(expr *ir.Expr) string {
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "selector":
		prefix := irQualifiedName(expr.Operand)
		if prefix == "" {
			return expr.Field
		}
		return prefix + "." + expr.Field
	default:
		return ""
	}
}
