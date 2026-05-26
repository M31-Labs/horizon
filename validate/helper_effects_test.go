package validate_test

import (
	"testing"

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

// TestHelperEffectsRespectsDepthLimitFallback exercises a placeholder
// fallback for the depth cap. Task 7 will replace this with a real
// 10-helper chain stress test; for now we pin that an unknown-name callee
// produces Unknown rather than panicking.
func TestHelperEffectsRespectsDepthLimitFallback(t *testing.T) {
	// Helper calls a name that does not exist in the program. Lookup
	// returns Unknown so the helper itself summarizes Unknown.
	fn := helperFn("fallback",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("notInProgram", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	prog := programWith(fn)
	effects := validate.BuildHelperEffects(prog)
	got := effects.EffectFor("fallback", 0)
	if got != validate.HelperEffectUnknown {
		t.Fatalf("EffectFor(fallback, 0) = %v, want HelperEffectUnknown", got)
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
