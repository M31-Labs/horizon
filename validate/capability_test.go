package validate

import (
	"testing"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func TestValidateCapabilityCoverageRequiresCoveredEntrypoints(t *testing.T) {
	program := ir.Program{
		Functions: []ir.Function{
			{Name: "helper"},
			{Name: "OnExec", Section: ir.Section{Kind: ir.ProgramTracepoint}},
			{Name: "Drop", Section: ir.Section{Kind: ir.ProgramXDP}},
		},
		Capabilities: []ir.Capability{
			{Name: "kernel.process.exec.observe", Program: "OnExec"},
		},
	}

	diags := ValidateCapabilityCoverage(program)
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %#v, want one uncovered program", diags)
	}
	if diags[0].Code != "HZN3301" || diags[0].Severity != diag.SeverityError {
		t.Fatalf("diagnostic = %#v, want HZN3301 error", diags[0])
	}
	if diags[0].Message == "" || diags[0].Suggest == "" {
		t.Fatalf("diagnostic = %#v, want actionable message and suggestion", diags[0])
	}
}

func TestValidateCapabilityCoverageAllowsFullyCoveredPrograms(t *testing.T) {
	program := ir.Program{
		Functions: []ir.Function{
			{Name: "OnExec", Section: ir.Section{Kind: ir.ProgramTracepoint}},
			{Name: "Drop", Section: ir.Section{Kind: ir.ProgramXDP}},
		},
		Capabilities: []ir.Capability{
			{Name: "kernel.process.exec.observe", Program: "OnExec"},
			{Name: "kernel.network.xdp.drop", Program: "Drop"},
		},
	}

	if diags := ValidateCapabilityCoverage(program); len(diags) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
}

func TestValidateCapabilitiesRejectsKnownKernelNamespaceMismatch(t *testing.T) {
	program := ir.Program{
		Functions: []ir.Function{
			{Name: "Drop", Section: ir.Section{Kind: ir.ProgramXDP}},
		},
		Capabilities: []ir.Capability{
			{Name: "kernel.process.exec.observe", Program: "Drop"},
		},
	}

	diags := ValidateCapabilities(program)
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %#v, want namespace mismatch", diags)
	}
	if diags[0].Code != "HZN2502" || diags[0].Severity != diag.SeverityError {
		t.Fatalf("diagnostic = %#v, want HZN2502 error", diags[0])
	}
}

func TestValidateCapabilitiesAllowsMatchingKnownKernelNamespace(t *testing.T) {
	program := ir.Program{
		Functions: []ir.Function{
			{Name: "Drop", Section: ir.Section{Kind: ir.ProgramXDP}},
			{Name: "Open", Section: ir.Section{Kind: ir.ProgramKprobe, Attach: "do_sys_openat2"}},
			{Name: "Connect", Section: ir.Section{Kind: ir.ProgramCgroup, Attach: "connect4"}},
		},
		Capabilities: []ir.Capability{
			{Name: "kernel.network.xdp.drop", Program: "Drop"},
			{Name: "kernel.file.open.observe", Program: "Open"},
			{Name: "kernel.network.connect.block", Program: "Connect"},
		},
	}

	if diags := ValidateCapabilities(program); len(diags) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
}

func TestValidateCapabilitiesLeavesCustomAndUnknownAttachNamespacesExtensible(t *testing.T) {
	program := ir.Program{
		Functions: []ir.Function{
			{Name: "Custom", Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_fork"}},
			{Name: "XDP", Section: ir.Section{Kind: ir.ProgramXDP}},
		},
		Capabilities: []ir.Capability{
			{Name: "kernel.process.fork.observe", Program: "Custom"},
			{Name: "com.example.network.xdp.audit", Program: "XDP"},
		},
	}

	if diags := ValidateCapabilities(program); len(diags) != 0 {
		t.Fatalf("diagnostics = %#v, want unknown attach/custom namespaces to pass", diags)
	}
}
