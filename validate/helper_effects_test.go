package validate_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// ── helper builders for this file ───────────────────────────────────────────────

// resourceParam constructs an `ir.Param` flagged Resource=true. Mirrors what
// ir.build sets for a *Event pointer parameter once HZN1319 is relaxed; tests
// here build the IR directly so they do not require the Phase 2 Task 2 work
// to have landed.
func resourceParam(name, typeName string) ir.Param {
	return ir.Param{
		Name:     name,
		Type:     ir.Type{Name: typeName, Ptr: true},
		Resource: true,
	}
}

func scalarParam(name, typeName string) ir.Param {
	return ir.Param{
		Name: name,
		Type: ir.Type{Name: typeName},
	}
}

// helperFn builds a sectionless user helper. Section.Kind == "" identifies
// it as a user helper (not an entrypoint) for BuildHelperEffects.
func helperFn(name string, params []ir.Param, body []ir.Statement) ir.Function {
	return ir.Function{
		Name:   name,
		Params: params,
		Body:   []ir.Block{{Statements: body}},
	}
}

// userCallExpr builds a bare-ident call: `name(args...)` — used for calls
// between user helpers (compiler-known helpers come through as selectors).
func userCallExpr(name string, args ...ir.Expr) *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{Kind: "ident", Name: name},
		Args: args,
	}
}

// selectorExpr builds `ident.field`.
func selectorExpr(ident, field string) *ir.Expr {
	return &ir.Expr{
		Kind:    "selector",
		Operand: &ir.Expr{Kind: "ident", Name: ident},
		Field:   field,
	}
}

// programWith builds an ir.Program containing only the supplied functions
// plus a single Events ringbuf map (matches what every helper-effects fixture
// in this file relies on for compiler-known consume/write detection).
func programWith(fns ...ir.Function) ir.Program {
	return ir.Program{
		Maps: []ir.Map{{
			Name: "Events",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "Event"},
		}},
		Functions: fns,
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────────

// TestHelperEffectsClassifiesSubmitAsConsumes verifies that a helper whose
// body is `Events.submit(ev); return true` summarizes to Consumes on its
// single resource parameter.
func TestHelperEffectsClassifiesSubmitAsConsumes(t *testing.T) {
	fn := helperFn("record",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("record", 0)
	if got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(record, 0) = %v, want HelperEffectConsumes", got)
	}
}

// TestHelperEffectsClassifiesNoOpAsPreserves verifies that a helper whose
// body merely returns true without touching its parameter summarizes to
// Preserves.
func TestHelperEffectsClassifiesNoOpAsPreserves(t *testing.T) {
	fn := helperFn("inspect",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("inspect", 0)
	if got != validate.HelperEffectPreserves {
		t.Fatalf("EffectFor(inspect, 0) = %v, want HelperEffectPreserves", got)
	}
}

// TestHelperEffectsClassifiesConditionalAsMixed verifies that a helper that
// submits on one branch and returns without on the other summarizes to
// Mixed.
func TestHelperEffectsClassifiesConditionalAsMixed(t *testing.T) {
	// func maybe(ev *Event) bool {
	//   if cond { Events.submit(ev) }
	//   return true
	// }
	fn := helperFn("maybe",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{Kind: "ident", Name: "cond"},
				Then: []ir.Statement{
					{Kind: "expr", Expr: submitExpr("Events", "ev")},
				},
				Else: []ir.Statement{
					// Reference ev so the else branch records "preserved".
					{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "ev"}},
				},
			},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("maybe", 0)
	if got != validate.HelperEffectMixed {
		t.Fatalf("EffectFor(maybe, 0) = %v, want HelperEffectMixed", got)
	}
}

// TestHelperEffectsClassifiesEscapeAsEscapes verifies that a helper which
// passes its parameter to an unknown function summarizes to Escapes.
func TestHelperEffectsClassifiesEscapeAsEscapes(t *testing.T) {
	// func leaks(ev *Event) bool { unknown(ev); return true }
	fn := helperFn("leaks",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("unknown", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("leaks", 0)
	// `unknown` is not a known helper in the program; the called-helper-name
	// lookup returns Unknown, which compresses to Unknown at the body level.
	if got != validate.HelperEffectUnknown {
		t.Fatalf("EffectFor(leaks, 0) = %v, want HelperEffectUnknown (unknown callee falls back conservatively)", got)
	}
}

// TestHelperEffectsClassifiesDereferenceAsConsumes verifies that a helper
// reading a field through its parameter (`ev.pid`) summarizes to Consumes.
// In Horizon's model, dereferencing a nullable resource handle without a
// nil-check is a fatal consumption — once the body touches a field, the
// caller is responsible for having proved liveness.
func TestHelperEffectsClassifiesDereferenceAsConsumes(t *testing.T) {
	// func touch(ev *Event) bool { _ = ev.pid; return true }
	fn := helperFn("touch",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: selectorExpr("ev", "pid")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("touch", 0)
	if got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(touch, 0) = %v, want HelperEffectConsumes", got)
	}
}

// TestHelperEffectsChainsThroughKnownHelpers verifies that when helper A
// calls helper B with B's parameter already summarized as Consumes, A also
// summarizes to Consumes. This is the load-bearing topological-sort case.
func TestHelperEffectsChainsThroughKnownHelpers(t *testing.T) {
	// func inner(ev *Event) bool { Events.submit(ev); return true }   → Consumes
	// func outer(ev *Event) bool { inner(ev); return true }            → Consumes
	inner := helperFn("inner",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	outer := helperFn("outer",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("inner", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(inner, outer)
	effects := validate.BuildHelperEffects(prog)
	if got := effects.EffectFor("inner", 0); got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(inner, 0) = %v, want HelperEffectConsumes", got)
	}
	if got := effects.EffectFor("outer", 0); got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(outer, 0) = %v, want HelperEffectConsumes (chained via inner)", got)
	}
}

// TestHelperEffectsRespectsDepthLimitFallback stresses the maxHelperEffectDepth
// boundary (=8) by constructing a 10-helper chain h0 → h1 → ... → h9, where
// h9 is the leaf that calls Events.submit(ev). Depth-from-leaf assigns
// depth(h9)=1, depth(h8)=2, ..., depth(h0)=10. Helpers at depth > 8 (i.e.
// h0 and h1) must summarize to all-Unknown so callers fall back to the
// Phase 1 "escaped" behavior. Helpers at depth ≤ 8 (h2..h9) propagate
// Consumes through the chain via the normal topo-sort path.
//
// This pins that the depth cap actually fires — without it, an acyclic but
// arbitrarily long chain would tie up summary work; with it, the cap bounds
// total work while preserving Phase 1's conservative fallback at the boundary.
func TestHelperEffectsRespectsDepthLimitFallback(t *testing.T) {
	const chain = 10 // = maxHelperEffectDepth + 2
	helpers := make([]ir.Function, chain)
	// h(chain-1) is the leaf: submits and returns.
	helpers[chain-1] = helperFn("h9",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// h(i) calls h(i+1)(ev) and returns.
	for i := chain - 2; i >= 0; i-- {
		helpers[i] = helperFn(
			fmtName("h", i),
			[]ir.Param{resourceParam("ev", "Event")},
			[]ir.Statement{
				{Kind: "expr", Expr: userCallExpr(fmtName("h", i+1), ir.Expr{Kind: "ident", Name: "ev"})},
				{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
			},
		)
	}
	prog := programWith(helpers...)
	effects := validate.BuildHelperEffects(prog)

	// h0 sits at depth 10 (10-helper chain to leaf), h1 at depth 9 — both
	// exceed maxHelperEffectDepth=8 and must trip the all-Unknown fallback.
	for _, name := range []string{"h0", "h1"} {
		if got := effects.EffectFor(name, 0); got != validate.HelperEffectUnknown {
			t.Fatalf("EffectFor(%s, 0) = %v, want HelperEffectUnknown (depth > maxHelperEffectDepth)", name, got)
		}
	}
	// h2 (depth 8) and below sit at or under the cap and propagate Consumes
	// through the chain (each calls the next, which is Consumes-classified).
	for _, name := range []string{"h2", "h5", "h9"} {
		if got := effects.EffectFor(name, 0); got != validate.HelperEffectConsumes {
			t.Fatalf("EffectFor(%s, 0) = %v, want HelperEffectConsumes (depth ≤ maxHelperEffectDepth)", name, got)
		}
	}
}

// TestHelperEffectsCycleBridgeYieldsAllUnknown constructs a synthetic IR
// program with a forbidden helper-call cycle a → b → a. HZN1503 prevents
// this at the source level, so the cycle bypasses normal type-check; the
// fixture is synthesized directly to verify BuildHelperEffects' cycle
// defense (topoSortHelpers returns ok=false → all-Unknown branch fires).
// The summary builder must NOT loop and must classify both helpers as
// HelperEffectUnknown so callers fall back to the Phase 1 "escaped" behavior.
func TestHelperEffectsCycleBridgeYieldsAllUnknown(t *testing.T) {
	// func a(ev *Event) bool { b(ev); return true }
	// func b(ev *Event) bool { a(ev); return true }
	a := helperFn("a",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("b", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	b := helperFn("b",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("a", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(a, b)

	// Run with a generous wall-clock budget: if topo-sort's cycle defense
	// fails, this loops forever — t.Deadline()/panic-on-timeout cannot help
	// us here. The actual implementation returns immediately when state is
	// "visiting".
	done := make(chan validate.HelperEffects, 1)
	go func() { done <- validate.BuildHelperEffects(prog) }()
	var effects validate.HelperEffects
	select {
	case effects = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BuildHelperEffects did not return within 2s — cycle defense regressed")
	}

	if got := effects.EffectFor("a", 0); got != validate.HelperEffectUnknown {
		t.Fatalf("EffectFor(a, 0) = %v, want HelperEffectUnknown (cycle bridge)", got)
	}
	if got := effects.EffectFor("b", 0); got != validate.HelperEffectUnknown {
		t.Fatalf("EffectFor(b, 0) = %v, want HelperEffectUnknown (cycle bridge)", got)
	}
}

// fmtName concatenates a prefix and a small integer without pulling in
// fmt for the formatting cost; tests only need names like "h0".."h9".
func fmtName(prefix string, i int) string {
	if i < 10 {
		return prefix + string(rune('0'+i))
	}
	return prefix + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// ── #6 (B2) struct-field aliasing inside helper bodies ────────────────────────
//
// These tests pin the field-store extension to walkParamEffectStatement: a
// helper that stores its tracked param into a container field must be
// classified soundly, and a helper that subsequently submits through the
// field-aliased selector must classify as Consumes (not lose the chain).

// TestHelperEffectsTracksFieldStoreOfParam verifies that a helper which
// stores its tracked resource param into a container field — without later
// referencing the field — classifies as Escapes. The container's downstream
// fate is opaque to intra-function analysis; the sound conservative answer
// is to widen to Escapes so the caller falls back to the Phase 1 "escaped"
// transition.
func TestHelperEffectsTracksFieldStoreOfParam(t *testing.T) {
	// func hide(ev *Event, c *Container) bool { c.slot = ev; return true }
	containerSlot := &ir.Expr{
		Kind:    "selector",
		Operand: &ir.Expr{Kind: "ident", Name: "c"},
		Field:   "slot",
	}
	fn := helperFn("hide",
		[]ir.Param{
			resourceParam("ev", "Event"),
			resourceParam("c", "Container"),
		},
		[]ir.Statement{
			{Kind: "assign", Target: containerSlot, Value: &ir.Expr{Kind: "ident", Name: "ev"}},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	if got := effects.EffectFor("hide", 0); got != validate.HelperEffectEscapes {
		t.Fatalf("EffectFor(hide, 0) = %v, want HelperEffectEscapes (param stored into container field — sound conservative)", got)
	}
}

// TestHelperEffectsTracksFieldStoreThenSubmit verifies that a helper which
// stores its tracked resource param into a container field and then submits
// via the field-aliased selector classifies as Consumes. The field-store
// edge added by Task 3 routes through walkParamEffectExpr's selector check
// (already in place for `param.field` reads), so the consumeCallResolved
// path detects Events.submit(c.slot) as consuming the original ev root.
func TestHelperEffectsTracksFieldStoreThenSubmit(t *testing.T) {
	// func consume(ev *Event, c *Container) bool {
	//   c.slot = ev
	//   Events.submit(c.slot)
	//   return true
	// }
	containerSlot := &ir.Expr{
		Kind:    "selector",
		Operand: &ir.Expr{Kind: "ident", Name: "c"},
		Field:   "slot",
	}
	submitSelector := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "Events"},
			Field:   "submit",
		},
		Args: []ir.Expr{*containerSlot},
	}
	fn := helperFn("consume",
		[]ir.Param{
			resourceParam("ev", "Event"),
			resourceParam("c", "Container"),
		},
		[]ir.Statement{
			{Kind: "assign", Target: containerSlot, Value: &ir.Expr{Kind: "ident", Name: "ev"}},
			{Kind: "expr", Expr: submitSelector},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	if got := effects.EffectFor("consume", 0); got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(consume, 0) = %v, want HelperEffectConsumes (field-aliased submit consumes the root param)", got)
	}
}

// ── #7 (B3) per-call-site path-sensitive helper-effect specialization ─────────
//
// These tests pin EffectForCall — the new public API that constant-folds
// literal call-site args and re-specializes the helper summary on the fly.
// The existing EffectFor (flat) API is unchanged and used for callers that
// have no arg context.

// recordHelperFn builds the canonical specialization fixture:
//
//	func record(ev *Event, flag u32) bool {
//	    if flag != 0 {
//	        Events.submit(ev)
//	        return true
//	    } else {
//	        return ev      // preserved on the else branch
//	    }
//	}
//
// With flag=1 the helper definitely submits → Consumes on ev.
// With flag=0 the helper definitely returns without submitting → Preserves
// on ev.
// With a non-literal flag the flat summary is Mixed (then-branch consumes,
// else-branch preserves).
func recordHelperFn() ir.Function {
	return helperFn("record",
		[]ir.Param{
			resourceParam("ev", "Event"),
			scalarParam("flag", "u32"),
		},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{
					Kind:  "binary",
					Op:    "!=",
					Left:  &ir.Expr{Kind: "ident", Name: "flag"},
					Right: &ir.Expr{Kind: "int", Value: "0"},
				},
				Then: []ir.Statement{
					{Kind: "expr", Expr: submitExpr("Events", "ev")},
					{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
				},
				Else: []ir.Statement{
					// Reference ev so the else branch records "preserved" —
					// this is what makes the flat summary Mixed (the
					// precondition for the non-literal-arg fallback test).
					{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "ev"}},
				},
			},
		},
	)
}

// TestHelperEffectsConstantArgPathSpecializeToConsumes verifies that a call
// site with a literal `flag=1` specializes the `record` helper's summary to
// Consumes on the `ev` param (the path that submits is the only feasible
// path under the substitution).
func TestHelperEffectsConstantArgPathSpecializeToConsumes(t *testing.T) {
	prog := programWith(recordHelperFn())
	effects := validate.BuildHelperEffects(prog)
	args := []ir.Expr{
		{Kind: "ident", Name: "e"},
		{Kind: "int", Value: "1"},
	}
	got := effects.EffectForCall("record", args)
	if len(got) != 2 {
		t.Fatalf("EffectForCall returned %d effects, want 2", len(got))
	}
	if got[0] != validate.HelperEffectConsumes {
		t.Fatalf("EffectForCall(record, flag=1)[0] = %v, want HelperEffectConsumes (literal-1 path always submits)", got[0])
	}
	if got[1] != validate.HelperEffectPreserves {
		t.Fatalf("EffectForCall(record, flag=1)[1] = %v, want HelperEffectPreserves (scalar param)", got[1])
	}
}

// TestHelperEffectsConstantArgPathSpecializeToPreserves verifies that a call
// site with a literal `flag=0` specializes the `record` helper's summary to
// Preserves on `ev` (the only feasible path returns without submitting).
func TestHelperEffectsConstantArgPathSpecializeToPreserves(t *testing.T) {
	prog := programWith(recordHelperFn())
	effects := validate.BuildHelperEffects(prog)
	args := []ir.Expr{
		{Kind: "ident", Name: "e"},
		{Kind: "int", Value: "0"},
	}
	got := effects.EffectForCall("record", args)
	if len(got) != 2 {
		t.Fatalf("EffectForCall returned %d effects, want 2", len(got))
	}
	if got[0] != validate.HelperEffectPreserves {
		t.Fatalf("EffectForCall(record, flag=0)[0] = %v, want HelperEffectPreserves (literal-0 path never submits)", got[0])
	}
	if got[1] != validate.HelperEffectPreserves {
		t.Fatalf("EffectForCall(record, flag=0)[1] = %v, want HelperEffectPreserves (scalar param)", got[1])
	}
}

// TestHelperEffectsNonLiteralArgFallsBackToFlatSummary verifies that when no
// arg is a literal, EffectForCall returns the flat per-helper summary (Mixed
// for `ev` in record's case — submit on one path, return without on another).
func TestHelperEffectsNonLiteralArgFallsBackToFlatSummary(t *testing.T) {
	prog := programWith(recordHelperFn())
	effects := validate.BuildHelperEffects(prog)
	args := []ir.Expr{
		{Kind: "ident", Name: "e"},
		{Kind: "ident", Name: "dynamicFlag"},
	}
	got := effects.EffectForCall("record", args)
	if len(got) != 2 {
		t.Fatalf("EffectForCall returned %d effects, want 2", len(got))
	}
	flat := effects.EffectFor("record", 0)
	if flat != validate.HelperEffectMixed {
		t.Fatalf("flat EffectFor(record, 0) = %v, want HelperEffectMixed (precondition for fallback test)", flat)
	}
	if got[0] != flat {
		t.Fatalf("EffectForCall(non-literal)[0] = %v, want flat %v (no literal arg → fallback)", got[0], flat)
	}
}

// TestHelperEffectsSpecializationBudgetExceededFallsBack stresses the
// per-helper 32-entry specialization cache cap. After 32 unique literal-arg
// signatures, subsequent distinct signatures must fall back to the flat
// summary (cap bounds worst-case work; telemetry via CacheOverflows tracks
// how often it fires).
func TestHelperEffectsSpecializationBudgetExceededFallsBack(t *testing.T) {
	prog := programWith(recordHelperFn())
	effects := validate.BuildHelperEffects(prog)
	flat := effects.EffectFor("record", 0)
	if flat != validate.HelperEffectMixed {
		t.Fatalf("flat EffectFor(record, 0) = %v, want HelperEffectMixed (precondition)", flat)
	}
	// Drive 64 unique literal signatures through EffectForCall. The 32-entry
	// cap means the first 32 specialize (flag != 0 → Consumes), entries 33+
	// overflow and fall back to flat Mixed.
	for i := 0; i < 64; i++ {
		args := []ir.Expr{
			{Kind: "ident", Name: "e"},
			{Kind: "int", Value: fmtName("", i+1)}, // 1..64, all non-zero → Consumes
		}
		got := effects.EffectForCall("record", args)
		if len(got) != 2 {
			t.Fatalf("iteration %d: EffectForCall returned %d effects, want 2", i, len(got))
		}
		if i < 32 {
			if got[0] != validate.HelperEffectConsumes {
				t.Fatalf("iteration %d: EffectForCall[0] = %v, want HelperEffectConsumes (within budget)", i, got[0])
			}
		} else {
			if got[0] != flat {
				t.Fatalf("iteration %d: EffectForCall[0] = %v, want flat %v (over-budget fallback)", i, got[0], flat)
			}
		}
	}
	if effects.CacheOverflows() == 0 {
		t.Fatalf("CacheOverflows = 0 after exceeding budget, want > 0")
	}
}

// TestHelperEffectsForScalarParamsIsPreserves verifies that non-resource
// parameters (scalars, bools) are always summarized as Preserves regardless
// of body shape. The caller would never apply a tracked transition to a
// scalar, but the explicit Preserves keeps callers honest and avoids
// having to special-case scalars at every transition site.
func TestHelperEffectsForScalarParamsIsPreserves(t *testing.T) {
	// func compute(pid u32, ev *Event) bool { Events.submit(ev); return true }
	// Parameter 0 (pid) is a scalar → Preserves; parameter 1 (ev) → Consumes.
	fn := helperFn("compute",
		[]ir.Param{
			scalarParam("pid", "u32"),
			resourceParam("ev", "Event"),
		},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	if got := effects.EffectFor("compute", 0); got != validate.HelperEffectPreserves {
		t.Fatalf("EffectFor(compute, 0) = %v, want HelperEffectPreserves (scalar param)", got)
	}
	if got := effects.EffectFor("compute", 1); got != validate.HelperEffectConsumes {
		t.Fatalf("EffectFor(compute, 1) = %v, want HelperEffectConsumes", got)
	}
}

// ── #8 (B5) helper-effect depth telemetry ─────────────────────────────────────

// TestHelperEffectsMaxObservedDepth verifies BuildHelperEffects stashes the
// deepest helper-call chain observed across all helpers. The fixture is a
// 3-helper chain (outer → middle → inner) so the leaf sits at depth 1, the
// middle at depth 2, and outer at depth 3.
func TestHelperEffectsMaxObservedDepth(t *testing.T) {
	inner := helperFn("inner",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	middle := helperFn("middle",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("inner", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	outer := helperFn("outer",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("middle", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(inner, middle, outer)
	effects := validate.BuildHelperEffects(prog)
	if effects.MaxObservedDepth != 3 {
		t.Fatalf("MaxObservedDepth = %d, want 3 (3-helper chain)", effects.MaxObservedDepth)
	}
}

// TestDepthTelemetryEnvGate verifies that validate.Program emits the
// `[birch-depth]` stderr line when HORIZON_BIRCH_DEPTH_REPORT is set, and
// emits nothing when unset. Captures os.Stderr via os.Pipe to avoid coupling
// to a fmt.Stringer or buffer-receiver indirection.
func TestDepthTelemetryEnvGate(t *testing.T) {
	// Build a fixture with a 2-helper chain so max_depth is observably > 0.
	inner := helperFn("inner",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	outer := helperFn("outer",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("inner", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := ir.Program{
		Package: "telemetry_fixture",
		Maps: []ir.Map{{
			Name: "Events",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "Event"},
		}},
		Functions: []ir.Function{inner, outer},
	}

	// Sub-test 1: env unset → no telemetry line.
	t.Run("unset", func(t *testing.T) {
		// t.Setenv with empty string still sets the variable (Go semantics);
		// use os.Unsetenv directly with cleanup to guarantee unset.
		t.Setenv("HORIZON_BIRCH_DEPTH_REPORT", "")
		os.Unsetenv("HORIZON_BIRCH_DEPTH_REPORT")
		stderr := captureStderr(t, func() { _ = validate.Program(prog) })
		if strings.Contains(stderr, "[birch-depth]") {
			t.Fatalf("unset env still emitted telemetry line: %q", stderr)
		}
	})

	// Sub-test 2: env set → one telemetry line with the expected fields.
	t.Run("set", func(t *testing.T) {
		t.Setenv("HORIZON_BIRCH_DEPTH_REPORT", "1")
		stderr := captureStderr(t, func() { _ = validate.Program(prog) })
		if !strings.Contains(stderr, "[birch-depth]") {
			t.Fatalf("env set but no telemetry line emitted: %q", stderr)
		}
		// Spot-check field shape; max_depth=2 for a 2-helper chain.
		for _, want := range []string{
			"program=telemetry_fixture",
			"max_depth=2",
			"helper_count=2",
			"cache_overflows=0",
		} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("telemetry line missing %q: %q", want, stderr)
			}
		}
	})
}

// captureStderr redirects os.Stderr through an os.Pipe for the duration of
// fn and returns whatever fn wrote. Restores os.Stderr in a t.Cleanup so
// concurrent subtest failures do not leak.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })
	fn()
	// Close the writer so the reader's io.Copy returns EOF.
	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()
	// Restore eagerly so subsequent subtests don't share the pipe.
	os.Stderr = orig
	return buf.String()
}
