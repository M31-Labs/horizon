package ir

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
)

func TestBuildFunctionTagsResourceTypedParam(t *testing.T) {
	file := ast.File{
		Package: "probes",
		Decls: []ast.Decl{
			ast.FuncDecl{
				Name: "record",
				Params: []ast.Param{
					{Name: "ev", Type: ast.TypeRef{Name: "Event", Ptr: true}},
					{Name: "flag", Type: ast.TypeRef{Name: "bool"}},
					{Name: "count", Type: ast.TypeRef{Name: "u32"}},
				},
				Return: ast.TypeRef{Name: "bool"},
			},
		},
	}
	program, _ := FromAST(file)
	if len(program.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(program.Functions))
	}
	fn := program.Functions[0]
	if len(fn.Params) != 3 {
		t.Fatalf("params = %d, want 3", len(fn.Params))
	}
	if !fn.Params[0].Resource {
		t.Fatalf("param[0] (ev *Event) Resource = false, want true")
	}
	if fn.Params[1].Resource {
		t.Fatalf("param[1] (flag bool) Resource = true, want false")
	}
	if fn.Params[2].Resource {
		t.Fatalf("param[2] (count u32) Resource = true, want false")
	}
}

func TestIsResourceParamTypeClassifiesScalarsAndPointers(t *testing.T) {
	cases := []struct {
		name string
		typ  Type
		want bool
	}{
		{"scalar u32", Type{Name: "u32"}, false},
		{"scalar bool", Type{Name: "bool"}, false},
		{"pointer to scalar u32", Type{Name: "u32", Ptr: true}, false},
		{"pointer to scalar bool", Type{Name: "bool", Ptr: true}, false},
		{"pointer to named struct", Type{Name: "Event", Ptr: true}, true},
		{"pointer to namespaced packet header", Type{Name: "xdp.Eth", Ptr: true}, true},
		{"array of u8 with Len", Type{Name: "u8", Len: "16", Ptr: true}, false},
		{"non-pointer named struct", Type{Name: "Event"}, false},
	}
	for _, tc := range cases {
		got := isResourceParamType(tc.typ)
		if got != tc.want {
			t.Errorf("isResourceParamType(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

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
