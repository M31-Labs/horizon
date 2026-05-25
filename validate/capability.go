package validate

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
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
	if cap.Name == "" || !strings.HasPrefix(cap.Name, "kernel.") {
		return diag.Diagnostic{}, false
	}
	want := expectedKernelCapabilityPrefix(fn.Section)
	if want == "" || strings.HasPrefix(cap.Name, want) {
		return diag.Diagnostic{}, false
	}
	return diag.Diagnostic{
		Code:     "HZN2502",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("capability %q does not match %s program %q", cap.Name, sectionDescription(fn.Section), fn.Name),
		Primary:  fn.Span,
		Suggest:  fmt.Sprintf("use a kernel capability prefixed with %q, or choose an attach surface that matches the capability", want),
	}, true
}

func expectedKernelCapabilityPrefix(section ir.Section) string {
	switch section.Kind {
	case ir.ProgramTracepoint:
		if section.Attach == "sched:sched_process_exec" {
			return "kernel.process.exec."
		}
	case ir.ProgramXDP:
		return "kernel.network.xdp."
	case ir.ProgramTC:
		return "kernel.network.tc."
	case ir.ProgramCgroup:
		if section.Attach == "connect4" || section.Attach == "connect6" {
			return "kernel.network.connect."
		}
	case ir.ProgramLSM:
		if section.Attach == "file_open" {
			return "kernel.file.open."
		}
	case ir.ProgramKprobe, ir.ProgramKretprobe:
		switch section.Attach {
		case "do_sys_openat2":
			return "kernel.file.open."
		case "tcp_v4_connect":
			return "kernel.network.tcp.connect."
		}
	}
	return ""
}

func sectionDescription(section ir.Section) string {
	if section.Kind == "" {
		return "sectionless"
	}
	if section.Attach == "" {
		return string(section.Kind)
	}
	return fmt.Sprintf("%s/%s", section.Kind, section.Attach)
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
