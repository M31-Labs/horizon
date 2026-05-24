package ir

import (
	"slices"
	"testing"
)

func TestMergeRefreshesCapabilityMapAccessAcrossPrograms(t *testing.T) {
	merged := Merge(
		Program{
			Package: "probes",
			Functions: []Function{{
				Name: "OnExec",
				Section: Section{
					Kind:   ProgramTracepoint,
					Attach: "sched:sched_process_exec",
					Name:   "tracepoint/sched/sched_process_exec",
				},
				Body: []Block{{
					Statements: []Statement{{
						Kind: "expr",
						Expr: &Expr{
							Kind: "call",
							Func: &Expr{
								Kind:  "selector",
								Field: "submit",
								Operand: &Expr{
									Kind: "ident",
									Name: "Events",
								},
							},
							Args: []Expr{{
								Kind: "ident",
								Name: "event",
							}},
						},
					}},
				}},
			}},
			Capabilities: []Capability{{
				Name:    "kernel.process.exec.observe",
				Kind:    CapabilitySource,
				Program: "OnExec",
			}},
		},
		Program{
			Maps: []Map{{
				Name: "Events",
				Kind: MapKindRingbuf,
				Val:  Type{Name: "Event"},
			}},
		},
	)
	if len(merged.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", merged.Capabilities)
	}
	capability := merged.Capabilities[0]
	if capability.Emits != "Event" || !slices.Contains(capability.Maps.Events, "Events") {
		t.Fatalf("capability = %#v, want refreshed Events emitter access", capability)
	}
}
