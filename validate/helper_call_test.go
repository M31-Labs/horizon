// Cross-call propagation tests for the helper-effects substrate.
//
// These tests exercise Phase 2 #13 (maple) Task 4 — when an entrypoint
// reserves a ringbuf reservation and then hands it to a user helper, the
// caller's reservation state machine reflects the helper's effect:
//
//   - Consumes  → live → consumed (later submit fires HZN2102)
//   - Preserves → live → live     (later return fires HZN2104)
//   - Mixed     → live → maybe_consumed (later return fires HZN2104)
//
// All fixtures build the IR directly so they do not depend on the source-
// level HZN1319 relaxation landing.
package validate_test

import (
	"testing"

	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// ringbufProgWithHelper builds an ir.Program with a ringbuf map "Events", a
// tracepoint entrypoint "Bad" whose body is entryStmts, and one or more user
// helpers. The helpers are placed BEFORE the entrypoint so the
// topological-sort order is deterministic regardless of program order.
func ringbufProgWithHelper(entryStmts []ir.Statement, helpers ...ir.Function) ir.Program {
	fns := make([]ir.Function, 0, len(helpers)+1)
	fns = append(fns, helpers...)
	fns = append(fns, ir.Function{
		Name:    "Bad",
		Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_exec"},
		Body:    []ir.Block{{Statements: entryStmts}},
	})
	return ir.Program{
		Maps: []ir.Map{{
			Name: "Events",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "Event"},
		}},
		Functions: fns,
	}
}

// TestRingbufLiveBecomesConsumedAfterHelperCall verifies that when an entrypoint
// reserves, nil-checks, calls a user helper that submits the reservation, and
// then attempts to submit it again, the validator fires HZN2102 (double-submit).
//
// Before Task 4: checkArgEscapesRingbuf marks the reservation "escaped", which
// suppresses BOTH the live-on-return and the double-submit diagnostics.
// After Task 4: applyHelperEffectRingbuf sees record's Consumes summary and
// transitions live → consumed, so the trailing Events.submit fires HZN2102.
func TestRingbufLiveBecomesConsumedAfterHelperCall(t *testing.T) {
	// helper: func record(ev *Event) bool { Events.submit(ev); return true }
	record := helperFn("record",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   record(event)
	//   Events.submit(event)   // HZN2102 — second consume
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("record", ir.Expr{Kind: "ident", Name: "event"})},
		{Kind: "expr", Expr: submitExpr("Events", "event")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, record)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2102"); got != 1 {
		t.Fatalf("HZN2102 count = %d, want 1 (helper Consumes effect should drive state to consumed)", got)
	}
}

// TestRingbufLiveStaysLiveAfterPreserveHelper verifies that when the helper
// merely inspects (does not submit) the reservation, the caller's state stays
// "live" through the call and HZN2104 (live-on-return) fires at the entry
// return point.
//
// Before Task 4: checkArgEscapesRingbuf marks the reservation "escaped",
// silencing HZN2104.
// After Task 4: applyHelperEffectRingbuf sees inspect's Preserves summary
// and leaves state untouched, so HZN2104 fires on the bare return.
func TestRingbufLiveStaysLiveAfterPreserveHelper(t *testing.T) {
	// helper: func inspect(ev *Event) bool { return true }  (never references ev)
	inspect := helperFn("inspect",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   inspect(event)
	//   return 0          // HZN2104 — live on return
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("inspect", ir.Expr{Kind: "ident", Name: "event"})},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, inspect)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (helper Preserves effect should leave state live)", got)
	}
}

// TestRingbufLiveBecomesMaybeConsumedAfterMixedHelper verifies that when the
// helper conditionally submits on one branch and returns without on the
// other, the caller's state transitions live → maybe_consumed, which still
// fires HZN2104 on the bare return (the lattice treats maybe_consumed as
// possibly live).
//
// Before Task 4: checkArgEscapesRingbuf marks the reservation "escaped",
// silencing HZN2104.
// After Task 4: applyHelperEffectRingbuf sees maybe's Mixed summary and
// transitions state to maybe_consumed; HZN2104 still fires.
func TestRingbufLiveBecomesMaybeConsumedAfterMixedHelper(t *testing.T) {
	// helper: func maybe(ev *Event) bool {
	//     if cond { Events.submit(ev) } else { return ev }
	//     return true
	// }
	maybe := helperFn("maybe",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{Kind: "ident", Name: "cond"},
				Then: []ir.Statement{
					{Kind: "expr", Expr: submitExpr("Events", "ev")},
				},
				Else: []ir.Statement{
					{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "ev"}},
				},
			},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   maybe(event)
	//   return 0          // HZN2104 — maybe_consumed still treated as possibly live
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("maybe", ir.Expr{Kind: "ident", Name: "event"})},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, maybe)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (helper Mixed effect should transition state to maybe_consumed)", got)
	}
}
