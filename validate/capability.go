package validate

import (
	"fmt"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func ValidateCapabilities(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	functions := map[string]ir.Function{}
	for _, fn := range program.Functions {
		functions[fn.Name] = fn
	}
	for _, cap := range program.Capabilities {
		if cap.Name == "" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2500",
				Severity: diag.SeverityError,
				Message:  "capability name is required",
			})
		}
		fn, ok := functions[cap.Program]
		if cap.Program == "" || !ok {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2501",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("capability %q references unknown program %q", cap.Name, cap.Program),
			})
			continue
		}
		if d, ok := capabilityNamespaceDiagnostic(cap, fn); ok {
			diags = append(diags, d)
		}
	}
	return diags
}

func capabilityNamespaceDiagnostic(cap ir.Capability, fn ir.Function) (diag.Diagnostic, bool) {
	section := manifestSectionForDiagnostic(fn.Section)
	want, mismatch := capability.KernelCapabilityNamespaceMismatch(cap.Name, string(fn.Section.Kind), fn.Section.Attach, section)
	if !mismatch {
		return diag.Diagnostic{}, false
	}
	return diag.Diagnostic{
		Code:     "HZN2502",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("capability %q does not match %s program %q", cap.Name, capability.ProgramSectionDescription(string(fn.Section.Kind), fn.Section.Attach, section), fn.Name),
		Primary:  capabilityPrimarySpan(cap, fn),
		Suggest:  fmt.Sprintf("use a kernel capability prefixed with %q, or choose an attach surface that matches the capability", want),
	}, true
}

func capabilityPrimarySpan(cap ir.Capability, fn ir.Function) span.Span {
	if !cap.Span.IsZero() {
		return cap.Span
	}
	return fn.Span
}

func manifestSectionForDiagnostic(section ir.Section) string {
	if section.Name != "" {
		return section.Name
	}
	return capability.ProgramSectionDescription(string(section.Kind), section.Attach, "")
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
