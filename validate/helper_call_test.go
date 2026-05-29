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

// ── #7 (B3) end-to-end caller-side specialization ─────────────────────────────

// recordFlagHelperFn mirrors recordHelperFn() in helper_effects_test.go but
// inline so this file does not couple test files. Same body shape:
//
//	func record(ev *Event, flag u32) bool {
//	    if flag != 0 { Events.submit(ev); return true }
//	    else { return ev }
//	}
//
// Flat summary on ev = Mixed (then-branch consumes, else-branch preserves);
// specialized with flag=1 → Consumes; specialized with flag=0 → Preserves.
func recordFlagHelperFn() ir.Function {
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
					{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "ev"}},
				},
			},
		},
	)
}

// TestRingbufHelperWithKnownPositiveFlagFiresDoubleSubmit verifies that
// per-call-site specialization correctly drives caller state when the helper
// is conditional on a literal arg.
//
// Baseline (v0.2, flat summary): record summarizes as Mixed on ev. Caller's
// state goes live → maybe_consumed → trailing Events.submit fires HZN2102
// (the maybe_consumed case in the consume-state switch already fires the
// double-submit diagnostic).
//
// v0.3 (#7 specialization): record(event, 1) specializes to Consumes on ev.
// Caller's state goes live → consumed → trailing Events.submit fires HZN2102
// (the consumed case fires the same diagnostic). No regression at the
// diagnostic level; precision improvement is observable at the EffectForCall
// API level (see TestHelperEffectsConstantArgPathSpecializeToConsumes).
//
// The precision gap that #7 closes — invisible at this test's diagnostic
// level — is for record(event, 0): v0.2 still widens to maybe_consumed and
// fires HZN2104 (live-on-return treats maybe_consumed as possibly live);
// v0.3 specializes to Preserves and fires HZN2104 from a cleaner "live"
// state. Both fire the same diagnostic at the entrypoint, but the
// specialized state is informationally tighter for downstream callers
// (e.g. a wrapping helper that itself classifies via record's effect).
func TestRingbufHelperWithKnownPositiveFlagFiresDoubleSubmit(t *testing.T) {
	record := recordFlagHelperFn()
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   record(event, 1)           // specialized → Consumes on ev
	//   Events.submit(event)        // HZN2102 — second consume
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("record",
			ir.Expr{Kind: "ident", Name: "event"},
			ir.Expr{Kind: "int", Value: "1"},
		)},
		{Kind: "expr", Expr: submitExpr("Events", "event")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, record)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2102"); got != 1 {
		t.Fatalf("HZN2102 count = %d, want 1 (specialized Consumes path drives state to consumed; trailing submit double-consumes)", got)
	}
}

// TestRingbufHelperWithKnownZeroFlagFiresLiveOnReturn verifies the dual case:
// when the literal arg makes the helper's submit path infeasible, the caller
// retains a live reservation and the bare return fires HZN2104.
//
// Baseline (v0.2): record summarizes as Mixed → state becomes maybe_consumed
// → HZN2104 fires (maybe_consumed treated as possibly live at return).
// v0.3: record(event, 0) specializes to Preserves → state stays live →
// HZN2104 fires. Same diagnostic, tighter underlying state.
func TestRingbufHelperWithKnownZeroFlagFiresLiveOnReturn(t *testing.T) {
	record := recordFlagHelperFn()
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   record(event, 0)            // specialized → Preserves on ev
	//   return 0                     // HZN2104 — live on return
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("record",
			ir.Expr{Kind: "ident", Name: "event"},
			ir.Expr{Kind: "int", Value: "0"},
		)},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, record)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (specialized Preserves leaves state live; bare return fires live-on-return)", got)
	}
}

// ── ReturnEffect caller-side consumption tests (v0.3 alder Phase 2, roadmap #18)

// resourceReturnHelperFnLocal mirrors the same helper-builder used in
// helper_effects_test.go for return-effect tests. Kept local so this test
// file is self-contained.
func resourceReturnHelperFnLocal(name string, params []ir.Param, body []ir.Statement, returnTypeName string) ir.Function {
	return ir.Function{
		Name:   name,
		Params: params,
		Return: ir.Type{Name: returnTypeName, Ptr: true},
		Body:   []ir.Block{{Statements: body}},
	}
}

// TestCallerBindsHelperReturnAsLiveResource pins that an entrypoint calling
// `e := make_event()` where make_event has verdict ReturnsResource (every
// path returns a fresh Events.reserve()) binds `e` as a live tracked
// resource. Submitting `e` directly afterward MUST be silent — neither
// HZN2101 (unknown reservation) nor HZN2100 (missing nil-check) should
// fire, because the helper guarantees a fresh non-nil handle.
func TestCallerBindsHelperReturnAsLiveResource(t *testing.T) {
	// helper: func make() *Event { return Events.reserve() }
	makeFn := resourceReturnHelperFnLocal("make",
		nil,
		[]ir.Statement{
			{Kind: "return", Value: reserveExpr("Events")},
		},
		"Event",
	)
	// entry:
	//   e := make()
	//   Events.submit(e)
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "e", Value: userCallExpr("make")},
		{Kind: "expr", Expr: submitExpr("Events", "e")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, makeFn)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2101"); got != 0 {
		t.Fatalf("HZN2101 count = %d, want 0 (ReturnsResource should bind e as a tracked reservation): %#v", got, diags)
	}
	if got := countDiag(diags, "HZN2100"); got != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (ReturnsResource implies never-nil, no nil-check required): %#v", got, diags)
	}
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (submit consumed the reservation): %#v", got, diags)
	}
}

// TestCallerBindsHelperReturnAsMaybeLiveResource pins that an entrypoint
// calling `e := maybeMake()` where maybeMake has verdict ReturnsResourceMaybe
// binds `e` as maybe_live: submitting `e` without a nil-check fires HZN2100
// (missing nil-check) — same diagnostic as a direct reserve site.
func TestCallerBindsHelperReturnAsMaybeLiveResource(t *testing.T) {
	// helper: func maybeMake(cond bool) *Event {
	//   if cond { return nil }
	//   return Events.reserve()
	// }
	maybeMake := resourceReturnHelperFnLocal("maybeMake",
		[]ir.Param{scalarParam("cond", "bool")},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{Kind: "ident", Name: "cond"},
				Then: []ir.Statement{
					{Kind: "return", Value: nilExpr()},
				},
			},
			{Kind: "return", Value: reserveExpr("Events")},
		},
		"Event",
	)
	// entry:
	//   cond := <dynamic>
	//   e := maybeMake(cond)    // non-literal cond → flat ReturnsResourceMaybe
	//   Events.submit(e)        // HZN2100 — submitted without nil-check
	//   return 0
	//
	// The cond is intentionally NON-literal so the per-call-site return
	// specialization (v0.4 B2) cannot prune the `if cond { return nil }`
	// branch — the call site keeps the flat ReturnsResourceMaybe verdict this
	// test was written to pin. The literal-arg case (where false prunes the
	// nil branch to a precise ReturnsResource and HZN2100 correctly does NOT
	// fire) is covered by TestCallerSpecializedReturnResourceNeedsNoNilCheck.
	entry := []ir.Statement{
		{Kind: "short_var", Name: "cond", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		{Kind: "short_var", Name: "e", Value: userCallExpr("maybeMake", ir.Expr{Kind: "ident", Name: "cond"})},
		{Kind: "expr", Expr: submitExpr("Events", "e")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, maybeMake)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2100"); got != 1 {
		t.Fatalf("HZN2100 count = %d, want 1 (ReturnsResourceMaybe must require nil-check before submit): %#v", got, diags)
	}
}

// TestCallerSpecializedReturnResourceNeedsNoNilCheck — SAFE-accept for the
// maybe→resource specialization. Calling `e := maybeMake(false)` prunes the
// `if cond { return nil }` branch (cond=false is infeasible for the nil path),
// so the per-call-site verdict resolves to the precise ReturnsResource: e is a
// definitely-live, never-nil handle. Submitting it without a nil-check must NOT
// fire HZN2100 — the conservative flat ReturnsResourceMaybe nil-check
// requirement is correctly relaxed for this literal-arg context because the
// helper provably returns a fresh non-nil resource under cond=false.
//
// Soundness sibling: TestCallerBindsHelperReturnAsMaybeLiveResource (above)
// proves the nil-check IS still required when the cond is non-literal and the
// nil branch cannot be pruned.
func TestCallerSpecializedReturnResourceNeedsNoNilCheck(t *testing.T) {
	maybeMake := resourceReturnHelperFnLocal("maybeMake",
		[]ir.Param{scalarParam("cond", "bool")},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{Kind: "ident", Name: "cond"},
				Then: []ir.Statement{
					{Kind: "return", Value: nilExpr()},
				},
			},
			{Kind: "return", Value: reserveExpr("Events")},
		},
		"Event",
	)
	// entry:
	//   e := maybeMake(false)   // false prunes nil branch → ReturnsResource
	//   Events.submit(e)        // no HZN2100 — provably non-nil
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "e", Value: userCallExpr("maybeMake", ir.Expr{Kind: "bool", Value: "false"})},
		{Kind: "expr", Expr: submitExpr("Events", "e")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, maybeMake)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2100"); got != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (cond=false prunes the nil branch → ReturnsResource, no nil-check required): %#v", got, diags)
	}
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (submit consumed the live binding): %#v", got, diags)
	}
}

// TestCallerArgumentEscapesOnReturnsAlias pins that an entrypoint passing a
// tracked reservation to a helper with verdict ReturnsAlias has the argument
// marked escaped — i.e. the trailing return does NOT fire HZN2104 (the
// helper has potentially exfiltrated the reservation via return).
func TestCallerArgumentEscapesOnReturnsAlias(t *testing.T) {
	// helper: func passthrough(e *Event) *Event { return e }
	passthrough := resourceReturnHelperFnLocal("passthrough",
		[]ir.Param{resourceParam("e", "Event")},
		[]ir.Statement{
			{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "e"}},
		},
		"Event",
	)
	// entry:
	//   event := Events.reserve()
	//   if event == nil { return 0 }
	//   passthrough(event)    // verdict ReturnsAlias — event escapes
	//   return 0              // no HZN2104 — escaped suppresses
	entry := []ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("passthrough", ir.Expr{Kind: "ident", Name: "event"})},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, passthrough)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (ReturnsAlias escapes the argument; suppression matches Phase 1 fallback): %#v", got, diags)
	}
}

// TestCallerUnknownReturnSuppressesDiagnostics pins that an entrypoint
// calling `e := opaque()` where opaque has verdict ReturnEffectUnknown
// produces no spurious diagnostics on the bound value — submitting `e`
// after must NOT fire HZN2101 (unknown reservation); the result is treated
// as escaped (not tracked) and downstream diagnostics are suppressed in
// the same way Phase 1 handled unsummarizable helpers.
func TestCallerUnknownReturnSuppressesDiagnostics(t *testing.T) {
	// helper: func opaque() *Event { return delegate() } where delegate
	// is itself a user helper returning *Event via reserve(). The opaque
	// helper's return verdict is Unknown (returns the result of another
	// user-helper call — not classifiable as fresh/nil/alias).
	delegate := resourceReturnHelperFnLocal("delegate",
		nil,
		[]ir.Statement{
			{Kind: "return", Value: reserveExpr("Events")},
		},
		"Event",
	)
	opaque := resourceReturnHelperFnLocal("opaque",
		nil,
		[]ir.Statement{
			{Kind: "return", Value: userCallExpr("delegate")},
		},
		"Event",
	)
	// entry:
	//   e := opaque()
	//   Events.submit(e)        // must NOT fire HZN2101 (Unknown suppresses)
	//   return 0
	entry := []ir.Statement{
		{Kind: "short_var", Name: "e", Value: userCallExpr("opaque")},
		{Kind: "expr", Expr: submitExpr("Events", "e")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, delegate, opaque)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2101"); got != 0 {
		t.Fatalf("HZN2101 count = %d, want 0 (Unknown return verdict must suppress downstream diagnostics on the bound value): %#v", got, diags)
	}
}

// ── Per-call-site ReturnEffect specialization, caller-side (v0.4 B2) ──────────
//
// These tests pin the consumer rewire: trackHelperReturnStatement and
// applyHelperEffectRingbuf now consult ReturnEffectForCall(helper, args)
// instead of the flat ReturnEffectFor(helper). A `flag`-gated helper whose flat
// verdict is Unknown resolves precisely under a literal flag, so the caller
// binds / escapes per the specialized verdict instead of the conservative
// Unknown→escaped posture. Each relaxation ships with its conservative sibling.

// chooseReturnHelperFnLocal builds the flag-gated return-specialization fixture
// used by the caller-side tests:
//
//	func choose(flag bool, e *Event) *Event {
//	    if flag { return e } else { return Events.reserve() }
//	}
//
// Flat classifyHelperReturns joins ReturnsAlias ⊔ ReturnsResource = Unknown.
// Under flag=false the only feasible return is the fresh Events.reserve()
// (ReturnsResource); under flag=true it is the alias return (ReturnsAlias).
func chooseReturnHelperFnLocal() ir.Function {
	return resourceReturnHelperFnLocal("choose",
		[]ir.Param{
			scalarParam("flag", "bool"),
			resourceParam("e", "Event"),
		},
		[]ir.Statement{
			{
				Kind: "if",
				Cond: &ir.Expr{Kind: "ident", Name: "flag"},
				Then: []ir.Statement{
					{Kind: "return", Value: &ir.Expr{Kind: "ident", Name: "e"}},
				},
				Else: []ir.Statement{
					{Kind: "return", Value: reserveExpr("Events")},
				},
			},
		},
		"Event",
	)
}

// The `src` reservation is always submitted explicitly in the entrypoint
// before/after the choose() call so it carries no leak obligation of its own.
// This isolates the assertion onto `e` (the binding produced by the return
// verdict) without HZN2104 noise from src. Passing an already-submitted ident
// as a short_var RHS arg is not itself a consume, so it raises no diagnostic.

// TestCallerBindsSpecializedReturnAsLiveUnderLiteral — SAFE-accept. The
// entrypoint binds `e := choose(false, src)`. Under flag=false the helper
// returns a fresh Events.reserve(), so ReturnEffectForCall specializes to
// ReturnsResource and trackHelperReturnStatement binds `e` as live. The
// entrypoint submits src (clearing its obligation) but NOT e, so HZN2104
// (live-on-return) fires for e — proving the binding is genuinely live. Under
// the v0.3 flat-Unknown verdict e would bind escaped, suppressing HZN2104.
func TestCallerBindsSpecializedReturnAsLiveUnderLiteral(t *testing.T) {
	choose := chooseReturnHelperFnLocal()
	// entry:
	//   src := Events.reserve()
	//   if src == nil { return 0 }
	//   Events.submit(src)        // clear src's own obligation
	//   e := choose(false, src)   // ReturnsResource under flag=false → e live
	//   return 0                  // HZN2104 — e is live on return
	entry := []ir.Statement{
		{Kind: "short_var", Name: "src", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("src"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: submitExpr("Events", "src")},
		{Kind: "short_var", Name: "e", Value: userCallExpr("choose",
			ir.Expr{Kind: "bool", Value: "false"},
			ir.Expr{Kind: "ident", Name: "src"},
		)},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, choose)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (specialized ReturnsResource binds e live; missing submit must leak): %#v", got, diags)
	}
}

// TestCallerBindsSpecializedReturnLiveCleanSubmit — SAFE-accept companion.
// Same `e := choose(false, src)` binding, but the entrypoint also submits `e`.
// The live binding is cleanly consumed: no HZN2104, no HZN2101 (e is a known
// reservation, not an unknown/escaped value).
func TestCallerBindsSpecializedReturnLiveCleanSubmit(t *testing.T) {
	choose := chooseReturnHelperFnLocal()
	entry := []ir.Statement{
		{Kind: "short_var", Name: "src", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("src"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: submitExpr("Events", "src")},
		{Kind: "short_var", Name: "e", Value: userCallExpr("choose",
			ir.Expr{Kind: "bool", Value: "false"},
			ir.Expr{Kind: "ident", Name: "src"},
		)},
		{Kind: "expr", Expr: submitExpr("Events", "e")},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, choose)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (submit consumed the live binding): %#v", got, diags)
	}
	if got := countDiag(diags, "HZN2101"); got != 0 {
		t.Fatalf("HZN2101 count = %d, want 0 (e is a known reservation, not escaped): %#v", got, diags)
	}
}

// TestCallerEscapesSpecializedAliasReturnUnderLiteral — UNSAFE-reject sibling.
// A statement-level call `choose(true, src)` specializes the return verdict to
// ReturnsAlias (the helper returns its arg), so applyHelperEffectRingbuf widens
// `src` to escaped — the helper may have exfiltrated it. The trailing bare
// return therefore does NOT fire HZN2104 on src (escape suppresses), matching
// the conservative posture for an exfiltrated resource. This proves the
// specialization correctly identifies the alias-escape rather than spuriously
// leaving src live. (Under the v0.3 flat-Unknown verdict src also escapes — via
// the param default — so the conservative posture is preserved either way; the
// win is that the escape is now driven by the *precise* ReturnsAlias verdict.)
func TestCallerEscapesSpecializedAliasReturnUnderLiteral(t *testing.T) {
	choose := chooseReturnHelperFnLocal()
	// entry:
	//   src := Events.reserve()
	//   if src == nil { return 0 }
	//   choose(true, src)   // ReturnsAlias under flag=true → src escapes
	//   return 0            // no HZN2104 — src exfiltrated via alias return
	entry := []ir.Statement{
		{Kind: "short_var", Name: "src", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("src"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: userCallExpr("choose",
			ir.Expr{Kind: "bool", Value: "true"},
			ir.Expr{Kind: "ident", Name: "src"},
		)},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, choose)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (specialized ReturnsAlias escapes src; suppression matches the exfiltration posture): %#v", got, diags)
	}
}

// TestCallerFallsBackToUnknownForNonLiteralFlag — conservative-fallback sibling.
// With a non-literal flag the return verdict cannot specialize; it stays the
// flat Unknown, so `e := choose(dynFlag, src)` binds e as escaped (the v0.3
// posture). src is submitted to clear its own obligation. The missing submit
// on e does NOT fire HZN2104 (escaped suppresses) — no unsound `live` binding
// on the un-prunable path. This pins the conservative fallback.
func TestCallerFallsBackToUnknownForNonLiteralFlag(t *testing.T) {
	choose := chooseReturnHelperFnLocal()
	entry := []ir.Statement{
		{Kind: "short_var", Name: "src", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("src"), Then: []ir.Statement{returnZero()}},
		{Kind: "expr", Expr: submitExpr("Events", "src")},
		{Kind: "short_var", Name: "dynFlag", Value: &ir.Expr{Kind: "bool", Value: "true"}},
		{Kind: "short_var", Name: "e", Value: userCallExpr("choose",
			ir.Expr{Kind: "ident", Name: "dynFlag"},
			ir.Expr{Kind: "ident", Name: "src"},
		)},
		returnZero(),
	}
	prog := ringbufProgWithHelper(entry, choose)
	diags := validate.Program(prog)
	if got := countDiag(diags, "HZN2104"); got != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (non-literal flag → flat Unknown → e bound escaped, no unsound live binding): %#v", got, diags)
	}
	if got := countDiag(diags, "HZN2101"); got != 0 {
		t.Fatalf("HZN2101 count = %d, want 0 (escaped binding suppresses downstream diagnostics): %#v", got, diags)
	}
}
