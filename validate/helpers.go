package validate

import (
	"fmt"
	"regexp"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

var helperCallRE = regexp.MustCompile(`\bbpf\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// AnalyzeHelpers runs the helpers validator's rule logic over pre-collected sites.
// For typed functions it consumes sites.HelperCall directly — no re-walk.
// For functions with only raw/text bodies, it falls back to the regex scan.
func AnalyzeHelpers(program ir.Program, sites Sites) []diag.Diagnostic {
	var diags []diag.Diagnostic

	// Typed path: each HelperCallSite carries the function and call expression.
	for _, site := range sites.HelperCall {
		name := irQualifiedName(site.Expr.Func)
		if name == "" || len(name) <= len("bpf.") || name[:len("bpf.")] != "bpf." {
			continue
		}
		helper := name[len("bpf."):]
		if helperAvailable(helper, site.Function.Section.Kind) {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN2300",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("helper bpf.%s is not available for %s programs", helper, site.Function.Section.Kind),
			Primary:  site.Expr.Span,
		})
	}

	// Legacy text path: functions without typed statements are not in Sites.
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
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
