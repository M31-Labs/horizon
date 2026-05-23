package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func ValidateMaps(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	for _, m := range program.Maps {
		switch m.Kind {
		case ir.MapKindRingbuf:
			if m.Val.Name == "" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2400",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("ringbuf map %q is missing a value type", m.Name),
				})
			}
		case ir.MapKindHash, ir.MapKindArray:
			if m.Key.Name == "" || m.Val.Name == "" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2401",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s map %q requires key and value types", m.Kind, m.Name),
				})
			}
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2402",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("unsupported map kind %q", m.Kind),
			})
		}
	}
	return diags
}
