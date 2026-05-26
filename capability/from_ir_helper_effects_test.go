package capability

import (
	"reflect"
	"testing"

	"m31labs.dev/horizon/ir"
)

// TestFromIRPopulatesHelperEffects_Observation pins the end-to-end
// IR -> manifest path for the simplest case: a program that only calls
// observation helpers (no map / ringbuf side-effects). The emitted
// Capability.HelperEffects must surface every recognized helper, sorted
// by Name, with the registry's observe vocabulary intact.
func TestFromIRPopulatesHelperEffects_Observation(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
			Body: []ir.Block{{Statements: []ir.Statement{
				exprStmt(dottedCallExpr("bpf", "current_pid")),
				exprStmt(dottedCallExpr("bpf", "current_uid")),
				exprStmt(dottedCallExpr("bpf", "ktime_get_ns")),
			}}},
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.observe",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
		}},
	})
	if len(m.Capabilities) != 1 {
		t.Fatalf("capabilities = %d, want 1", len(m.Capabilities))
	}
	got := m.Capabilities[0].HelperEffects
	wantNames := []string{"bpf.current_pid", "bpf.current_uid", "bpf.ktime_get_ns"}
	if len(got) != len(wantNames) {
		t.Fatalf("HelperEffects = %+v, want %d entries", got, len(wantNames))
	}
	for i, name := range wantNames {
		if got[i].Name != name {
			t.Fatalf("HelperEffects[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
	// bpf.current_pid carries observes:[task.tgid] per registry.
	if !reflect.DeepEqual(got[0].Observes, []string{"task.tgid"}) {
		t.Fatalf("HelperEffects[0].Observes = %+v, want [task.tgid]", got[0].Observes)
	}
}

// TestFromIRPopulatesHelperEffects_RingbufLifecycle exercises the
// resource-verb path end-to-end: a program that reserves and submits a
// ringbuf entry must emit two HelperEffect rows, both with "ringbuf:$"
// substituted to the concrete map name and the matching resource verb
// preserved.
func TestFromIRPopulatesHelperEffects_RingbufLifecycle(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnOpen",
			Section: ir.Section{
				Kind:   ir.ProgramKprobe,
				Name:   "kprobe/do_sys_openat2",
				Attach: "do_sys_openat2",
			},
			Body: []ir.Block{{Statements: []ir.Statement{
				exprStmt(methodCallExpr("OpenEvents", "reserve")),
				exprStmt(methodCallExpr("OpenEvents", "submit")),
			}}},
		}},
		Maps: []ir.Map{{
			Name: "OpenEvents",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "OpenEvent"},
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.file.open.observe",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnOpen",
			Section: "kprobe/do_sys_openat2",
			Maps: ir.CapabilityMapAccess{
				Events: []string{"OpenEvents"},
			},
		}},
	})
	if len(m.Capabilities) != 1 {
		t.Fatalf("capabilities = %d, want 1", len(m.Capabilities))
	}
	got := m.Capabilities[0].HelperEffects
	want := []HelperEffect{
		{Name: "ringbuf.reserve", Mutates: []string{"ringbuf:OpenEvents"}, Resource: "reserve"},
		{Name: "ringbuf.submit", Mutates: []string{"ringbuf:OpenEvents"}, Resource: "submit"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HelperEffects = %+v, want %+v", got, want)
	}
}

// TestFromIRPopulatesHelperEffects_MapLifecycle covers the map verbs
// (lookup / update / delete) so the placeholder substitution path is
// exercised across both observes ("map:$" -> "map:<name>") and mutates
// channels. Lookup lands in observes; update / delete land in mutates.
func TestFromIRPopulatesHelperEffects_MapLifecycle(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
			Body: []ir.Block{{Statements: []ir.Statement{
				exprStmt(methodCallExpr("Counts", "lookup")),
				exprStmt(methodCallExpr("Counts", "update")),
				exprStmt(methodCallExpr("Counts", "delete")),
			}}},
		}},
		Maps: []ir.Map{{
			Name: "Counts",
			Kind: ir.MapKindHash,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "u64"},
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.count",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
			Maps: ir.CapabilityMapAccess{
				Read:  []string{"Counts"},
				Write: []string{"Counts"},
			},
		}},
	})
	if len(m.Capabilities) != 1 {
		t.Fatalf("capabilities = %d, want 1", len(m.Capabilities))
	}
	got := m.Capabilities[0].HelperEffects
	want := []HelperEffect{
		{Name: "map.delete", Mutates: []string{"map:Counts"}, Resource: "delete"},
		{Name: "map.lookup", Observes: []string{"map:Counts"}, Resource: "lookup"},
		{Name: "map.update", Mutates: []string{"map:Counts"}, Resource: "update"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HelperEffects = %+v, want %+v", got, want)
	}
}

// TestFromIRPopulatesHelperEffects_OmitemptyWhenNoHelpers pins the
// no-helper case: a program with no annotated helper calls must surface
// a nil HelperEffects slice on its Capability so that JSON serialization
// elides the "helper_effects" key entirely. Coupled with the omitempty
// unit test on Capability itself, this guarantees pre-Phase-2 manifests
// gain no spurious "helper_effects":[] entries.
func TestFromIRPopulatesHelperEffects_OmitemptyWhenNoHelpers(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
			// Empty body — no helper calls reachable.
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.observe",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
		}},
	})
	if len(m.Capabilities) != 1 {
		t.Fatalf("capabilities = %d, want 1", len(m.Capabilities))
	}
	if m.Capabilities[0].HelperEffects != nil {
		t.Fatalf("HelperEffects = %+v, want nil for program with no helpers", m.Capabilities[0].HelperEffects)
	}
}
