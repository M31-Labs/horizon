// Cross-call propagation tests for the helper-effects substrate.
//
// These tests exercise Phase 2 #13 (maple) Tasks 4–6 — when an entrypoint
// produces a tracked resource (ringbuf reservation, map lookup, packet
// header) and then hands it to a user helper, the caller's state machine
// reflects the helper's effect:
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

// ── Task 5: maps caller propagation ───────────────────────────────────────────

// lookupExpr builds: Counts.lookup(pid)
func lookupExpr(mapName, keyName string) *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: mapName},
			Field:   "lookup",
		},
		Args: []ir.Expr{{Kind: "ident", Name: keyName}},
	}
}

// lookupProgWithHelper builds an ir.Program with a hash map "Counts" of type
// Counter, a tracepoint entrypoint "Bad" whose body is entryStmts, and one or
// more user helpers. Helpers are placed BEFORE the entrypoint so the
// topological-sort order is deterministic.
func lookupProgWithHelper(entryStmts []ir.Statement, helpers ...ir.Function) ir.Program {
	fns := make([]ir.Function, 0, len(helpers)+1)
	fns = append(fns, helpers...)
	fns = append(fns, ir.Function{
		Name:    "Bad",
		Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_exec"},
		Body:    []ir.Block{{Statements: entryStmts}},
	})
	return ir.Program{
		Maps: []ir.Map{{
			Name: "Counts",
			Kind: ir.MapKindHash,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "Counter"},
		}},
		Functions: fns,
	}
}

// TestMapLookupDerefFiresAfterPreserveHelper verifies that when the helper
// merely inspects the lookup pointer without dereferencing it, the caller's
// `maybe_nil` state is NOT widened to `escaped` — so a trailing unguarded
// deref still fires HZN2500. This is the load-bearing case for maps: the
// Phase 1 fallback eagerly widens `maybe_nil` → `escaped` on any call,
// over-suppressing the deref check after the helper returns.
//
// Before Task 5: checkArgEscapesLookup marks the lookup result "escaped",
// silencing HZN2500.
// After Task 5: applyHelperEffectLookup sees inspect's Preserves summary
// and leaves the state untouched, so the trailing `count.seen = 1` fires
// HZN2500.
func TestMapLookupDerefFiresAfterPreserveHelper(t *testing.T) {
	// helper: func inspect(cnt *Counter) bool { return true }  (never references cnt)
	inspect := helperFn("inspect",
		[]ir.Param{resourceParam("cnt", "Counter")},
		[]ir.Statement{
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   count := Counts.lookup(pid)
	//   inspect(count)
	//   count.seen = 1   // HZN2500 — never nil-checked
	//   return 0
	countSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("count"),
		Field:   "seen",
	}
	entry := []ir.Statement{
		{Kind: "short_var", Name: "count", Value: lookupExpr("Counts", "pid")},
		{Kind: "expr", Expr: userCallExpr("inspect", ir.Expr{Kind: "ident", Name: "count"})},
		{Kind: "assign", Target: countSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
		returnZero(),
	}
	prog := lookupProgWithHelper(entry, inspect)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2500"); got != 1 {
		t.Fatalf("HZN2500 count = %d, want 1 (Preserves should stop over-suppression of unguarded deref)", got)
	}
}

// TestMapLookupConsumeHelperDocumentsConsumption documents the expected
// current behavior when a helper "consumes" (dereferences) a lookup pointer.
// For maps, the caller's lookup-state machine is concerned only with whether
// the caller has proven the pointer non-nil before dereferencing; whether the
// helper itself dereferenced is irrelevant to the caller's diagnostic
// obligations. After the helper returns, the caller still does not know
// liveness, so an unguarded deref by the caller should still fire HZN2500.
//
// This test pins that Consumes does NOT change the caller's behavior —
// matching the plan's lattice for maps (Consumes is equivalent to Preserves
// at the caller side, because lookup pointers aren't "owned").
func TestMapLookupConsumeHelperDocumentsConsumption(t *testing.T) {
	// helper: func touch(cnt *Counter) bool { _ = cnt.seen; return true }
	// Helper dereferences cnt → summarized as Consumes.
	touch := helperFn("touch",
		[]ir.Param{resourceParam("cnt", "Counter")},
		[]ir.Statement{
			{Kind: "expr", Expr: selectorExpr("cnt", "seen")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   count := Counts.lookup(pid)
	//   touch(count)
	//   count.seen = 1   // HZN2500 — caller never nil-checked
	//   return 0
	countSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("count"),
		Field:   "seen",
	}
	entry := []ir.Statement{
		{Kind: "short_var", Name: "count", Value: lookupExpr("Counts", "pid")},
		{Kind: "expr", Expr: userCallExpr("touch", ir.Expr{Kind: "ident", Name: "count"})},
		{Kind: "assign", Target: countSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
		returnZero(),
	}
	prog := lookupProgWithHelper(entry, touch)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2500"); got != 1 {
		t.Fatalf("HZN2500 count = %d, want 1 (Consumes should not suppress caller deref check)", got)
	}
}

// ── Task 6: packet caller propagation ─────────────────────────────────────────

// xdpEthExpr builds: xdp.eth(ctx)
func xdpEthExpr() *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "xdp"},
			Field:   "eth",
		},
		Args: []ir.Expr{{Kind: "ident", Name: "ctx"}},
	}
}

// xdpProgWithHelper builds an ir.Program with an XDP entrypoint "Bad" whose
// body is entryStmts and one or more user helpers placed BEFORE the
// entrypoint for deterministic topological order.
func xdpProgWithHelper(entryStmts []ir.Statement, helpers ...ir.Function) ir.Program {
	fns := make([]ir.Function, 0, len(helpers)+1)
	fns = append(fns, helpers...)
	fns = append(fns, ir.Function{
		Name:    "Bad",
		Section: ir.Section{Kind: ir.ProgramXDP, Name: "xdp"},
		Body:    []ir.Block{{Statements: entryStmts}},
	})
	return ir.Program{Functions: fns}
}

// TestPacketHeaderDerefFiresAfterPreserveHelper verifies that when the helper
// merely inspects the packet header pointer without dereferencing it, the
// caller's `maybe_nil` state is NOT widened to `escaped` — so a trailing
// unguarded deref still fires HZN2600. Mirrors the map-lookup case: the
// Phase 1 fallback eagerly widens `maybe_nil` → `escaped` on any call,
// over-suppressing the deref check after the helper returns.
//
// Before Task 6: checkArgEscapesPacket marks the header "escaped",
// silencing HZN2600.
// After Task 6: applyHelperEffectPacket sees inspect's Preserves summary
// and leaves the state untouched, so the trailing `eth.proto` access fires
// HZN2600.
func TestPacketHeaderDerefFiresAfterPreserveHelper(t *testing.T) {
	// helper: func inspect(eth *xdp.Eth) bool { return true }  (never references eth)
	inspect := helperFn("inspect",
		[]ir.Param{resourceParam("eth", "Eth")},
		[]ir.Statement{
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// entry:
	//   eth := xdp.eth(ctx)
	//   inspect(eth)
	//   if eth.proto == 0 { return 0 }   // HZN2600 — never nil-checked
	//   return 0
	ethProto := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("eth"),
		Field:   "proto",
	}
	entry := []ir.Statement{
		{Kind: "short_var", Name: "eth", Value: xdpEthExpr()},
		{Kind: "expr", Expr: userCallExpr("inspect", ir.Expr{Kind: "ident", Name: "eth"})},
		{
			Kind: "if",
			Cond: &ir.Expr{
				Kind:  "binary",
				Op:    "==",
				Left:  ethProto,
				Right: &ir.Expr{Kind: "int", Value: "0"},
			},
			Then: []ir.Statement{returnZero()},
		},
		returnZero(),
	}
	prog := xdpProgWithHelper(entry, inspect)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2600"); got != 1 {
		t.Fatalf("HZN2600 count = %d, want 1 (Preserves should stop over-suppression of unguarded packet deref)", got)
	}
}

// TestRingbufConsumesPropagatesAcrossThreeHelperChain stresses cross-call
// propagation through a 3-helper chain: outer(ev) → middle(ev) → inner(ev),
// where inner is the leaf that calls Events.submit. The summary builder
// topologically classifies inner=Consumes, then middle=Consumes (because its
// only act is calling inner with the param), then outer=Consumes (same).
// The entrypoint reserves, nil-checks, calls outer(event), then attempts a
// second submit — the chain-of-three must drive event from live to consumed
// so HZN2102 fires on the trailing submit.
//
// This pins the Phase 2 #13 end-to-end story: deep helper chains carry the
// consume effect to the caller, not just one-hop helpers.
func TestRingbufConsumesPropagatesAcrossThreeHelperChain(t *testing.T) {
	// func inner(ev *Event) bool { Events.submit(ev); return true }
	inner := helperFn("inner",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: submitExpr("Events", "ev")},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// func middle(ev *Event) bool { inner(ev); return true }
	middle := helperFn("middle",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("inner", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)
	// func outer(ev *Event) bool { middle(ev); return true }
	outer := helperFn("outer",
		[]ir.Param{resourceParam("ev", "Event")},
		[]ir.Statement{
			{Kind: "expr", Expr: userCallExpr("middle", ir.Expr{Kind: "ident", Name: "ev"})},
			{Kind: "return", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		},
	)

	// First confirm the summary chain classifies all three as Consumes —
	// this is the load-bearing pre-condition for the entrypoint diagnostic.
	prog := ringbufProgWithHelper(nil, inner, middle, outer)
	effects := validate.BuildHelperEffects(prog)
	for _, name := range []string{"inner", "middle", "outer"} {
		if got := effects.EffectFor(name, 0); got != validate.HelperEffectConsumes {
			t.Fatalf("EffectFor(%s, 0) = %v, want HelperEffectConsumes (3-helper chain)", name, got)
		}
	}

	// Now build the actual entrypoint that double-submits via the chain:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   outer(event)             // chain drives state to consumed
	//   Events.submit(event)     // HZN2102 — second consume
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("outer", ir.Expr{Kind: "ident", Name: "event"})},
		{Kind: "expr", Expr: submitExpr("Events", "event")},
		returnZero(),
	}
	prog = ringbufProgWithHelper(entry, inner, middle, outer)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2102"); got != 1 {
		t.Fatalf("HZN2102 count = %d, want 1 (3-helper chain should consume through to caller)", got)
	}
}
