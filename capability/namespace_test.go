package capability

import "testing"

func TestKernelCapabilityNamespaceMismatchUsesKnownAttachSurfacePrefixes(t *testing.T) {
	tests := []struct {
		name       string
		capability string
		kind       string
		attach     string
		section    string
		want       string
		mismatch   bool
	}{
		{name: "xdp matches", capability: "kernel.network.xdp.drop", kind: "xdp", want: "kernel.network.xdp."},
		{name: "xdp mismatch", capability: "kernel.process.exec.observe", kind: "xdp", want: "kernel.network.xdp.", mismatch: true},
		{name: "tracepoint attach matches", capability: "kernel.process.exec.observe", kind: "tracepoint", attach: "sched:sched_process_exec", want: "kernel.process.exec."},
		{name: "manifest section fallback", capability: "kernel.network.connect.block", kind: "cgroup", section: "cgroup/connect4", want: "kernel.network.connect."},
		{name: "custom namespace stays open", capability: "com.example.network.xdp.audit", kind: "xdp"},
		{name: "unknown attach stays open", capability: "kernel.process.fork.observe", kind: "tracepoint", attach: "sched:sched_process_fork"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, mismatch := KernelCapabilityNamespaceMismatch(tc.capability, tc.kind, tc.attach, tc.section)
			if got != tc.want || mismatch != tc.mismatch {
				t.Fatalf("KernelCapabilityNamespaceMismatch() = %q, %v; want %q, %v", got, mismatch, tc.want, tc.mismatch)
			}
		})
	}
}

func TestProgramSectionDescription(t *testing.T) {
	if got := ProgramSectionDescription("tracepoint", "sched:sched_process_exec", ""); got != "tracepoint/sched:sched_process_exec" {
		t.Fatalf("description = %q, want tracepoint attach", got)
	}
	if got := ProgramSectionDescription("xdp", "", "xdp"); got != "xdp" {
		t.Fatalf("description = %q, want section", got)
	}
}
