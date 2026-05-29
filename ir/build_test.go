package ir

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
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

// TestFromPackagesTagsOriginPackage verifies that FromPackages tags every
// declaration coming from a dependency package with the dependency's import
// alias as its Origin, while declarations from the root package keep an
// empty Origin string. This is the cross-package equivalent of single-file
// FromAST and is the entry point compiler.AnalyzePath consumes for
// multi-package builds (roadmap #20 Phase 2 Subtask 4a).
func TestFromPackagesTagsOriginPackage(t *testing.T) {
	rootFile := ast.File{
		Package: "main",
		Decls: []ast.Decl{
			ast.TypeDecl{Name: "RootEvent"},
			ast.MapDecl{Name: "Events", Kind: "ringbuf", Val: ast.TypeRef{Name: "RootEvent"}},
			ast.CapabilityDecl{Name: "Observe", Value: "kernel.process.exec.observe", Danger: "observe"},
		},
	}
	root := ast.Package{
		Name:  "main",
		Files: []ast.File{rootFile},
		ImportEdges: []ast.ImportEdge{
			{Alias: "events", ResolvedPath: "/abs/events"},
		},
	}
	depFile := ast.File{
		Package: "events",
		Decls: []ast.Decl{
			ast.TypeDecl{Name: "ExecEvent"},
			ast.ConstDecl{Name: "MaxBufSize", Type: ast.TypeRef{Name: "u32"}, Value: ast.IntExpr{Value: "4096"}},
			ast.CapabilityDecl{Name: "ExecObserve", Value: "kernel.process.exec.observe", Danger: "observe"},
		},
	}
	dep := ast.Package{Name: "events", Files: []ast.File{depFile}}

	graph := ImportGraph{
		PackageAliases: map[string]string{"/abs/events": "events"},
	}

	program, diags := FromPackages(root, []ast.Package{dep}, graph)
	if hasErr := diag.HasErrors(diags); hasErr {
		t.Fatalf("FromPackages emitted error diagnostics: %#v", diags)
	}
	wantRoot := map[string]bool{"RootEvent": true}
	wantDep := map[string]string{"ExecEvent": "events"}
	for _, s := range program.Structs {
		if wantRoot[s.Name] && s.Origin != "" {
			t.Errorf("root struct %s Origin = %q, want empty", s.Name, s.Origin)
		}
		if want, ok := wantDep[s.Name]; ok && s.Origin != want {
			t.Errorf("dep struct %s Origin = %q, want %q", s.Name, s.Origin, want)
		}
	}
	for _, c := range program.Constants {
		if c.Name == "MaxBufSize" && c.Origin != "events" {
			t.Errorf("dep const MaxBufSize Origin = %q, want events", c.Origin)
		}
	}
	for _, m := range program.Maps {
		if m.Name == "Events" && m.Origin != "" {
			t.Errorf("root map Events Origin = %q, want empty", m.Origin)
		}
	}
}

// TestFromPackagesRejectsConflictingFunctionsAcrossPackages verifies that
// when two packages contribute a Function with the same qualified name but
// different bodies, Merge surfaces a typed diagnostic instead of silently
// keeping the first or last. Qualified-name = Origin + "." + Name when
// Origin != "", else bare Name. Two root functions with the same name
// remain caught by the existing types-layer HZN1002.
func TestMergeDetectsCrossPackageFunctionCollision(t *testing.T) {
	a := Program{
		Functions: []Function{{
			Name:     "Helper",
			Origin:   "events",
			BodyText: "return 0",
		}},
	}
	b := Program{
		Functions: []Function{{
			Name:     "Helper",
			Origin:   "events",
			BodyText: "return 1",
		}},
	}
	_, diags := MergeWithDiagnostics(a, b)
	if !diag.HasErrors(diags) {
		t.Fatalf("MergeWithDiagnostics with conflicting bodies = %#v, want HZN15xx error", diags)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1562" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want one with Code=HZN1562", diags)
	}
}

// TestBuildStructOpsMap verifies that a struct_ops map declaration lowers to an
// ir.Map with Kind == MapKindStructOps and the kernel ops-struct name as its
// value type, and that the new kind is excluded from every lookup predicate
// (it is not a hash/array/percpu/lru map). This is the IR half of the v0.4
// Track A A2 struct_ops runtime-attach work (decision 0010).
func TestBuildStructOpsMap(t *testing.T) {
	file := ast.File{
		Package: "probes",
		Decls: []ast.Decl{
			ast.MapDecl{
				Name: "Ops",
				Kind: ast.MapKindStructOps,
				Val:  ast.TypeRef{Name: "tcp_congestion_ops"},
			},
		},
	}
	program, diags := FromAST(file)
	if diag.HasErrors(diags) {
		t.Fatalf("FromAST diagnostics = %#v, want none", diags)
	}
	if len(program.Maps) != 1 {
		t.Fatalf("maps = %d, want 1", len(program.Maps))
	}
	m := program.Maps[0]
	if m.Kind != MapKindStructOps {
		t.Fatalf("map kind = %q, want %q", m.Kind, MapKindStructOps)
	}
	if m.Val.Name != "tcp_congestion_ops" {
		t.Fatalf("map value type = %q, want tcp_congestion_ops", m.Val.Name)
	}
	if m.Kind.IsLookup() || m.Kind.IsHashLike() || m.Kind.IsArrayLike() || m.Kind.HasPerCPUValue() {
		t.Fatalf("struct_ops kind classified as a lookup map: IsLookup=%v IsHashLike=%v IsArrayLike=%v HasPerCPUValue=%v",
			m.Kind.IsLookup(), m.Kind.IsHashLike(), m.Kind.IsArrayLike(), m.Kind.HasPerCPUValue())
	}
}
