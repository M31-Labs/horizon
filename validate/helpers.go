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
