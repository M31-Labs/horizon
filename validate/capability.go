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

func ValidateCapabilityCoverage(program ir.Program) []diag.Diagnostic {
	covered := map[string]bool{}
	for _, cap := range program.Capabilities {
		if cap.Program != "" {
			covered[cap.Program] = true
		}
	}
	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if fn.Section.Kind == "" || covered[fn.Name] {
			continue
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN3301",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("program %q must declare a capability before Horizon artifacts can be generated", fn.Name),
			Primary:  fn.Span,
			Suggest:  "declare a package capability with explicit danger and reference it with @capability(Name)",
		})
	}
	return diags
}
