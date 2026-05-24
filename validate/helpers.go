package validate

import (
	"fmt"
	"regexp"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

var helperCallRE = regexp.MustCompile(`\bbpf\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

func ValidateHelpers(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
			diags = append(diags, validateTypedHelpers(fn)...)
			continue
		}
		for _, line := range bodyLines(fn) {
			for _, match := range helperCallRE.FindAllStringSubmatch(line, -1) {
				helper := match[1]
				if helperAvailable(helper, fn.Section.Kind) {
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

func validateTypedHelpers(fn ir.Function) []diag.Diagnostic {
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
		if helperAvailable(helper, fn.Section.Kind) {
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

func helperAvailable(name string, kind ir.ProgramKind) bool {
	switch name {
	case "current_pid", "current_ppid", "current_uid", "current_comm":
		return isTracingProgram(kind)
	case "probe_read_user_str":
		return kind == ir.ProgramKprobe
	case "ktime_get_ns":
		return knownProgramKind(kind)
	default:
		return false
	}
}

func knownProgramKind(kind ir.ProgramKind) bool {
	switch kind {
	case ir.ProgramTracepoint, ir.ProgramKprobe, ir.ProgramKretprobe, ir.ProgramXDP, ir.ProgramTC, ir.ProgramCgroup, ir.ProgramLSM:
		return true
	default:
		return false
	}
}

func isTracingProgram(kind ir.ProgramKind) bool {
	switch kind {
	case ir.ProgramTracepoint, ir.ProgramKprobe, ir.ProgramKretprobe:
		return true
	default:
		return false
	}
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
			if stmt.Init != nil {
				walkStatements([]ir.Statement{*stmt.Init}, visit)
			}
			walkExpr(stmt.Cond, visit)
			walkStatements(stmt.Then, visit)
			walkStatements(stmt.Else, visit)
		case "for":
			if stmt.Init != nil {
				walkStatements([]ir.Statement{*stmt.Init}, visit)
			}
			walkExpr(stmt.Cond, visit)
			if stmt.Post != nil {
				walkStatements([]ir.Statement{*stmt.Post}, visit)
			}
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
	for i := range expr.Fields {
		walkExpr(&expr.Fields[i].Value, visit)
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
