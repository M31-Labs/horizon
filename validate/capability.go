package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func ValidateCapabilities(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	functions := map[string]bool{}
	for _, fn := range program.Functions {
		functions[fn.Name] = true
	}
	for _, cap := range program.Capabilities {
		if cap.Name == "" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2500",
				Severity: diag.SeverityError,
				Message:  "capability name is required",
			})
		}
		if cap.Program == "" || !functions[cap.Program] {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2501",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("capability %q references unknown program %q", cap.Name, cap.Program),
			})
		}
	}
	return diags
}
