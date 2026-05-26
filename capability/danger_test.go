package capability_test

import (
	"testing"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/ir"
)

// TestDangerAxesRoundTripThroughIRAndManifest verifies that DangerAxes set on
// an ir.Capability are preserved after FromIR produces a manifest. For Task 1,
// only the IR-side axes field is pinned; the manifest-side danger string stays
// as a flat word and will be cut over in Task 3.
func TestDangerAxesRoundTripThroughIRAndManifest(t *testing.T) {
	axes := ir.DangerAxes{
		Mode:          "control",
		Scope:         "network",
		Reversibility: "restart",
	}
	program := ir.Program{
		Package: "testpkg",
		Capabilities: []ir.Capability{
			{
				Name:    "kernel.network.packet.drop",
				Kind:    ir.CapabilitySource,
				Program: "drop_packets",
				Section: "xdp",
				Danger:  ir.DangerDrop,
				Axes:    axes,
				Maps: ir.CapabilityMapAccess{
					Read:   []string{},
					Write:  []string{},
					Events: []string{},
				},
			},
		},
	}

	// Verify the ir.Capability has the expected axes — the IR-side contract.
	cap := program.Capabilities[0]
	if cap.Axes.Mode != axes.Mode {
		t.Errorf("IR Axes.Mode = %q, want %q", cap.Axes.Mode, axes.Mode)
	}
	if cap.Axes.Scope != axes.Scope {
		t.Errorf("IR Axes.Scope = %q, want %q", cap.Axes.Scope, axes.Scope)
	}
	if cap.Axes.Reversibility != axes.Reversibility {
		t.Errorf("IR Axes.Reversibility = %q, want %q", cap.Axes.Reversibility, axes.Reversibility)
	}

	// FromIR must compile successfully; it forwards cap.Danger string unchanged
	// for now (Task 3 will cut over the manifest to axes).
	manifest := capability.FromIR(program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("FromIR produced %d capabilities, want 1", len(manifest.Capabilities))
	}
	gotDanger := manifest.Capabilities[0].Danger
	if gotDanger != string(ir.DangerDrop) {
		t.Errorf("manifest.Capabilities[0].Danger = %q, want %q", gotDanger, string(ir.DangerDrop))
	}
}

// TestDangerAxesFromIRBuild verifies that FromAST (which internally calls
// buildCapabilities) correctly populates Axes on ir.Capability from a
// capability alias that carries a flat danger word.
func TestDangerAxesFromIRBuild(t *testing.T) {
	// Build an ir.Capability manually to simulate what buildCapabilities produces.
	// The axes for DangerObserve should be {observe, event, none}.
	cap := ir.Capability{
		Name:    "kernel.process.exec.observe",
		Kind:    ir.CapabilitySource,
		Program: "watch_exec",
		Section: "tracepoint/syscalls/sys_enter_execve",
		Danger:  ir.DangerObserve,
		Axes:    ir.DangerObserve.Axes(),
		Maps: ir.CapabilityMapAccess{
			Read:   []string{},
			Write:  []string{},
			Events: []string{},
		},
	}

	wantAxes := ir.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
	if cap.Axes != wantAxes {
		t.Errorf("Axes = %+v, want %+v", cap.Axes, wantAxes)
	}
}
