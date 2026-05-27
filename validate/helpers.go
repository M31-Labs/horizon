package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

// AnalyzeHelpers runs the helpers validator's rule logic over pre-collected sites.
// It consumes sites.HelperCall directly from the typed-IR index.
func AnalyzeHelpers(program ir.Program, sites Sites) []diag.Diagnostic {
	var diags []diag.Diagnostic

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
	case ir.ProgramTracepoint, ir.ProgramKprobe, ir.ProgramKretprobe,
		ir.ProgramXDP, ir.ProgramTC, ir.ProgramCgroup, ir.ProgramLSM,
		ir.ProgramUprobe, ir.ProgramUretprobe,
		ir.ProgramFentry, ir.ProgramFexit,
		ir.ProgramRawTP, ir.ProgramSockOps, ir.ProgramStructOps:
		return true
	default:
		return false
	}
}

func isTracingProgram(kind ir.ProgramKind) bool {
	switch kind {
	case ir.ProgramTracepoint, ir.ProgramKprobe, ir.ProgramKretprobe,
		ir.ProgramUprobe, ir.ProgramUretprobe,
		ir.ProgramFentry, ir.ProgramFexit,
		ir.ProgramRawTP:
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
