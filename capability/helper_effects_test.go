package capability

import (
	"reflect"
	"testing"

	"m31labs.dev/horizon/ir"
)

// TestLookupHelperEffectsByName exercises the public LookupHelperEffects
// accessor end-to-end against the embedded registry. The accessor is the
// integration handle downstream consumers (notably the maple track's
// helper-effect summary lattice in roadmap #13) call into; the table
// covers the three behavioural cases:
//
//   - a static observation helper (no map / ringbuf placeholder) — the
//     template surfaces with its observe vocabulary unchanged.
//   - a ringbuf resource helper — the template surfaces with its
//     placeholder "ringbuf:$" preserved verbatim, deferring substitution
//     to ComputeHelperEffectsForFunction at emit time.
//   - an unknown name — the accessor reports (_, false) without
//     allocating a default template.
func TestLookupHelperEffectsByName(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		want    HelperEffectTemplate
		wantOk  bool
	}{
		{
			name:   "static observation helper",
			query:  "bpf.current_pid",
			want:   HelperEffectTemplate{Name: "bpf.current_pid", Observes: []string{"task.tgid"}},
			wantOk: true,
		},
		{
			name:   "ringbuf resource helper preserves placeholder",
			query:  "ringbuf.reserve",
			want:   HelperEffectTemplate{Name: "ringbuf.reserve", Mutates: []string{"ringbuf:$"}, Resource: "reserve"},
			wantOk: true,
		},
		{
			name:   "current_ppid carries BTF requires",
			query:  "bpf.current_ppid",
			want:   HelperEffectTemplate{Name: "bpf.current_ppid", Observes: []string{"task.real_parent.tgid"}, Requires: []string{"task_struct.real_parent"}},
			wantOk: true,
		},
		{
			name:   "unknown helper returns false",
			query:  "bpf.unknown_helper",
			want:   HelperEffectTemplate{},
			wantOk: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := LookupHelperEffects(tc.query)
			if ok != tc.wantOk {
				t.Fatalf("LookupHelperEffects(%q) ok = %v, want %v", tc.query, ok, tc.wantOk)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("LookupHelperEffects(%q) = %+v, want %+v", tc.query, got, tc.want)
			}
		})
	}
}

// TestLookupHelperEffectsReturnsIndependentSlices guards the immutability
// promise the plan locks in §D-5: callers may freely mutate the slices
// they receive without poisoning the registry. The accessor must hand out
// fresh copies of every slice field — observe / mutate / requires — so a
// downstream consumer that wants to append a substituted token cannot
// corrupt the underlying singleton.
func TestLookupHelperEffectsReturnsIndependentSlices(t *testing.T) {
	first, ok := LookupHelperEffects("ringbuf.reserve")
	if !ok {
		t.Fatalf("ringbuf.reserve missing from registry")
	}
	if len(first.Mutates) == 0 {
		t.Fatalf("ringbuf.reserve has no mutates entry")
	}
	first.Mutates[0] = "ringbuf:CORRUPTED"

	second, ok := LookupHelperEffects("ringbuf.reserve")
	if !ok {
		t.Fatalf("ringbuf.reserve missing from registry on second lookup")
	}
	if second.Mutates[0] != "ringbuf:$" {
		t.Fatalf("registry mutates slice was poisoned: got %q, want %q", second.Mutates[0], "ringbuf:$")
	}
}

// --- ComputeHelperEffectsForFunction (Subtask 2b) ---

// callExpr builds a minimal call IR expression of the form "ident(...)".
// Convenience for the table-driven aggregation tests below. The Args
// slice intentionally stays empty — the walker keys off the call's
// Func node, not its arguments.
func callExpr(name string) ir.Expr {
	return ir.Expr{
		Kind: "call",
		Func: &ir.Expr{Kind: "ident", Name: name},
	}
}

// dottedCallExpr builds a qualified call IR expression of the form
// "<prefix>.<field>(...)". Used to drive recognition of bpf.current_pid
// and the like, which arrive as selector-on-ident calls in the IR.
func dottedCallExpr(prefix, field string) ir.Expr {
	return ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Field:   field,
			Operand: &ir.Expr{Kind: "ident", Name: prefix},
		},
	}
}

// methodCallExpr builds a receiver.method() IR call shape — the form
// the parser produces for map / ringbuf invocations such as
// "OpenEvents.reserve(...)". The receiver becomes the substitution
// target for any "map:$" / "ringbuf:$" placeholders in the registry.
func methodCallExpr(receiver, method string) ir.Expr {
	return ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Field:   method,
			Operand: &ir.Expr{Kind: "ident", Name: receiver},
		},
	}
}

// exprStmt wraps a single call expression as a top-level statement
// inside a function body. The walker only inspects calls that surface
// during the IR walk, so wrapping the call in a statement is the
// minimum we need to drive the aggregation pipeline end-to-end.
func exprStmt(expr ir.Expr) ir.Statement {
	cp := expr
	return ir.Statement{Kind: "expr", Expr: &cp}
}

// programFromFns assembles a single-program ir.Program from a list of
// functions for the walker tests. The first function is the entry; any
// remaining functions are user-defined callees the walker should reach
// via the reachableFunctions recursion.
func programFromFns(fns ...ir.Function) ir.Program {
	return ir.Program{Functions: fns}
}

func TestComputeHelperEffectsForFunction_Empty(t *testing.T) {
	fn := ir.Function{
		Name:    "Empty",
		Section: ir.Section{Kind: ir.ProgramKprobe},
	}
	got := ComputeHelperEffectsForFunction(programFromFns(fn), fn)
	if got != nil {
		t.Fatalf("expected nil for function with no helpers, got %+v", got)
	}
}

func TestComputeHelperEffectsForFunction_SingleCall(t *testing.T) {
	call := dottedCallExpr("bpf", "current_pid")
	fn := ir.Function{
		Name:    "Single",
		Section: ir.Section{Kind: ir.ProgramKprobe},
		Body:    []ir.Block{{Statements: []ir.Statement{exprStmt(call)}}},
	}
	got := ComputeHelperEffectsForFunction(programFromFns(fn), fn)
	want := []HelperEffect{
		{Name: "bpf.current_pid", Observes: []string{"task.tgid"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ComputeHelperEffectsForFunction = %+v, want %+v", got, want)
	}
}

func TestComputeHelperEffectsForFunction_DedupedAcrossCalls(t *testing.T) {
	call := dottedCallExpr("bpf", "current_pid")
	fn := ir.Function{
		Name:    "Dup",
		Section: ir.Section{Kind: ir.ProgramKprobe},
		Body: []ir.Block{{Statements: []ir.Statement{
			exprStmt(call),
			exprStmt(call),
			exprStmt(call),
		}}},
	}
	got := ComputeHelperEffectsForFunction(programFromFns(fn), fn)
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped entry, got %d (%+v)", len(got), got)
	}
	if got[0].Name != "bpf.current_pid" {
		t.Fatalf("entry name = %q, want bpf.current_pid", got[0].Name)
	}
}

func TestComputeHelperEffectsForFunction_SubstitutesMapName(t *testing.T) {
	cases := []struct {
		name     string
		receiver string
		method   string
		want     HelperEffect
	}{
		{
			name:     "ringbuf reserve substitutes receiver",
			receiver: "OpenEvents",
			method:   "reserve",
			want:     HelperEffect{Name: "ringbuf.reserve", Mutates: []string{"ringbuf:OpenEvents"}, Resource: "reserve"},
		},
		{
			name:     "ringbuf submit substitutes receiver",
			receiver: "OpenEvents",
			method:   "submit",
			want:     HelperEffect{Name: "ringbuf.submit", Mutates: []string{"ringbuf:OpenEvents"}, Resource: "submit"},
		},
		{
			name:     "ringbuf discard substitutes receiver",
			receiver: "Events",
			method:   "discard",
			want:     HelperEffect{Name: "ringbuf.discard", Mutates: []string{"ringbuf:Events"}, Resource: "discard"},
		},
		{
			name:     "map lookup substitutes receiver into observes",
			receiver: "Counts",
			method:   "lookup",
			want:     HelperEffect{Name: "map.lookup", Observes: []string{"map:Counts"}, Resource: "lookup"},
		},
		{
			name:     "map update substitutes receiver into mutates",
			receiver: "Counts",
			method:   "update",
			want:     HelperEffect{Name: "map.update", Mutates: []string{"map:Counts"}, Resource: "update"},
		},
		{
			name:     "map delete substitutes receiver into mutates",
			receiver: "Counts",
			method:   "delete",
			want:     HelperEffect{Name: "map.delete", Mutates: []string{"map:Counts"}, Resource: "delete"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn := ir.Function{
				Name:    "Sub",
				Section: ir.Section{Kind: ir.ProgramKprobe},
				Body: []ir.Block{{Statements: []ir.Statement{
					exprStmt(methodCallExpr(tc.receiver, tc.method)),
				}}},
			}
			got := ComputeHelperEffectsForFunction(programFromFns(fn), fn)
			if len(got) != 1 {
				t.Fatalf("expected 1 entry, got %d (%+v)", len(got), got)
			}
			if !reflect.DeepEqual(got[0], tc.want) {
				t.Fatalf("entry = %+v, want %+v", got[0], tc.want)
			}
		})
	}
}

// TestComputeHelperEffectsForFunction_AggregatesAcrossReachable
// exercises the reachableFunctions recursion: helper effects emitted
// in a user-defined callee must surface in the caller's aggregate.
func TestComputeHelperEffectsForFunction_AggregatesAcrossReachable(t *testing.T) {
	callee := ir.Function{
		Name: "callee",
		// No Section → recognized as a user function by reachableFunctions.
		Body: []ir.Block{{Statements: []ir.Statement{
			exprStmt(dottedCallExpr("bpf", "current_uid")),
		}}},
	}
	caller := ir.Function{
		Name:    "Caller",
		Section: ir.Section{Kind: ir.ProgramKprobe},
		Body: []ir.Block{{Statements: []ir.Statement{
			exprStmt(callExpr("callee")),
		}}},
	}
	program := programFromFns(caller, callee)
	got := ComputeHelperEffectsForFunction(program, caller)

	found := false
	for _, eff := range got {
		if eff.Name == "bpf.current_uid" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bpf.current_uid in aggregate (callee-reachable), got %+v", got)
	}
}

func TestComputeHelperEffectsForFunction_SortedByName(t *testing.T) {
	fn := ir.Function{
		Name:    "Sort",
		Section: ir.Section{Kind: ir.ProgramKprobe},
		Body: []ir.Block{{Statements: []ir.Statement{
			// Intentionally insert out-of-order — must come out sorted by Name.
			exprStmt(methodCallExpr("OpenEvents", "submit")),
			exprStmt(dottedCallExpr("bpf", "ktime_get_ns")),
			exprStmt(dottedCallExpr("bpf", "current_pid")),
			exprStmt(methodCallExpr("OpenEvents", "reserve")),
		}}},
	}
	got := ComputeHelperEffectsForFunction(programFromFns(fn), fn)
	wantOrder := []string{
		"bpf.current_pid",
		"bpf.ktime_get_ns",
		"ringbuf.reserve",
		"ringbuf.submit",
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("entry count = %d, want %d (%+v)", len(got), len(wantOrder), got)
	}
	for i, eff := range got {
		if eff.Name != wantOrder[i] {
			t.Fatalf("entry[%d].Name = %q, want %q (%+v)", i, eff.Name, wantOrder[i], got)
		}
	}
}

// TestComputeHelperEffectsForFunction_RegistryImmutableAfterSubstitution
// pins the §D-5 immutability guarantee: even after the walker has
// substituted a concrete map name into a placeholder, the registry's
// underlying template must still surface the "$" sentinel on a fresh
// lookup. Failure here would mean the walker mutated the registry copy
// in place, which would silently poison subsequent calls.
func TestComputeHelperEffectsForFunction_RegistryImmutableAfterSubstitution(t *testing.T) {
	fn := ir.Function{
		Name:    "Mut",
		Section: ir.Section{Kind: ir.ProgramKprobe},
		Body: []ir.Block{{Statements: []ir.Statement{
			exprStmt(methodCallExpr("OpenEvents", "reserve")),
		}}},
	}
	_ = ComputeHelperEffectsForFunction(programFromFns(fn), fn)

	tmpl, ok := LookupHelperEffects("ringbuf.reserve")
	if !ok {
		t.Fatalf("ringbuf.reserve missing from registry after substitution")
	}
	if len(tmpl.Mutates) != 1 || tmpl.Mutates[0] != "ringbuf:$" {
		t.Fatalf("registry template was poisoned by substitution: %+v", tmpl)
	}
}
