// Package validate_test exercises the loop-carry state analysis added in
// Phase 1 Track A Task 3 (#5). The bounded 2-iteration fixpoint detects
// resource-state regressions across loop iterations (e.g. double-submit).
//
// All tests use synthetic in-memory ir.Program fixtures following the
// conventions in aliasing_test.go. The double-submit-in-loop real .hzn
// fixture (testdata/invalid/ringbuf_double_submit_in_loop.hzn) is exercised
// separately via compiler/compile_test.go::TestAnalyzeInvalidRingbufPrograms.
//
// Debt (acknowledged in plan §3.4 Q1): `continue` is not in the v0.2 grammar;
// the valid reserve-in-loop fixture uses early `return 0` instead of `continue`.
package validate_test

import (
	"testing"

	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// forStmt builds a minimal for-statement: for i := 0; i < N; i++ { body... }
func forStmt(body []ir.Statement) ir.Statement {
	return ir.Statement{
		Kind: "for",
		Init: &ir.Statement{
			Kind:  "short_var",
			Name:  "i",
			Value: &ir.Expr{Kind: "int", Value: "0"},
		},
		Cond: &ir.Expr{
			Kind:  "binary",
			Op:    "<",
			Left:  &ir.Expr{Kind: "ident", Name: "i"},
			Right: &ir.Expr{Kind: "int", Value: "4"},
		},
		Post: &ir.Statement{
			Kind: "expr",
			Expr: &ir.Expr{
				Kind:    "unary",
				Op:      "++",
				Operand: &ir.Expr{Kind: "ident", Name: "i"},
			},
		},
		Body: body,
	}
}

// ── Step 3.2: double-submit detected in loop (ringbuf) ────────────────────────

// TestLoopCarryDetectsDoubleSubmitInsideForBody verifies that submitting a
// ringbuf reservation inside a for-loop body without re-reserving per iteration
// fires at least one HZN2102 (submit-more-than-once). Without the bounded
// 2-iteration fixpoint, the body is walked once and the second iteration's
// double-submit is never checked.
//
// Equivalent to testdata/invalid/ringbuf_double_submit_in_loop.hzn:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	for i := 0; i < 4; i++ {
//	    Events.submit(event)
//	}
//	return 0
func TestLoopCarryDetectsDoubleSubmitInsideForBody(t *testing.T) {
	loopBody := []ir.Statement{
		exprStmt(submitExpr("Events", "event")),
	}

	prog := ringbufProg([]ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event == nil { return 0 }
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		// for loop that double-submits
		forStmt(loopBody),
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2102 := countDiag(diags, "HZN2102")
	if hzn2102 != 1 {
		t.Fatalf("HZN2102 count = %d, want exactly 1 (double-submit inside loop should be caught once by fixpoint; dedup prevents duplicate emission)", hzn2102)
	}
}

// ── Step 3.4: valid reserve-submit per iteration stays accepted ───────────────

// TestLoopCarryAcceptsReserveSubmitInsideForBody verifies that a sound
// reserve→nil-check→submit pattern executed per iteration produces zero
// ringbuf diagnostics. The fixpoint should reach stability because after
// each body execution `event` ends in "consumed" state, and re-entering
// the body re-declares `event` via short_var (reset to "maybe_nil").
//
// Because `continue` is not in the v0.2 grammar, the nil branch uses early
// `return 0` rather than `continue`. The fixpoint must handle this without
// falsely flagging the pattern as unsound.
//
// Equivalent to:
//
//	for i := 0; i < 4; i++ {
//	    event := Events.reserve()
//	    if event == nil { return 0 }
//	    Events.submit(event)
//	}
//	return 0
func TestLoopCarryAcceptsReserveSubmitInsideForBody(t *testing.T) {
	loopBody := []ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event == nil { return 0 }
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		// Events.submit(event)
		exprStmt(submitExpr("Events", "event")),
	}

	prog := ringbufProg([]ir.Statement{
		forStmt(loopBody),
		returnZero(),
	})

	diags := validate.Program(prog)
	for _, d := range diags {
		switch d.Code {
		case "HZN2100", "HZN2102", "HZN2103", "HZN2104":
			t.Errorf("unexpected ringbuf diagnostic %s: %s (valid reserve-per-iteration pattern must not be flagged)", d.Code, d.Message)
		}
	}
}

// ── Step 3.5: write-after-submit detected in loop (ringbuf) ──────────────────

// TestLoopCarryDetectsWriteAfterSubmitInsideForBody verifies that writing to a
// ringbuf reservation inside a loop after it has already been submitted (outside
// the loop) fires at least one HZN2103 (write-after-submit). The first
// iteration of the fixpoint walk catches this because the state is already
// "consumed" entering the loop body.
//
// Equivalent to:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	Events.submit(event)
//	for i := 0; i < 4; i++ {
//	    event.pid = 1   // write-after-submit (HZN2103)
//	}
//	return 0
func TestLoopCarryDetectsWriteAfterSubmitInsideForBody(t *testing.T) {
	// event.pid = 1 as an assignment statement
	writeAfterSubmit := ir.Statement{
		Kind: "assign",
		Target: &ir.Expr{
			Kind:    "selector",
			Operand: identExpr("event"),
			Field:   "pid",
		},
		Value: &ir.Expr{Kind: "int", Value: "1"},
	}

	loopBody := []ir.Statement{writeAfterSubmit}

	prog := ringbufProg([]ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event == nil { return 0 }
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		// Events.submit(event)
		exprStmt(submitExpr("Events", "event")),
		// for loop with write after submit
		forStmt(loopBody),
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2103 := countDiag(diags, "HZN2103")
	if hzn2103 != 1 {
		t.Fatalf("HZN2103 count = %d, want exactly 1 (write-after-submit inside loop should be caught once; dedup prevents duplicate emission)", hzn2103)
	}
}

// ── Step 3.6: maps unguarded deref in loop ────────────────────────────────────

// TestLoopCarryDetectsUnguardedDerefInsideForBody verifies that dereferencing
// a map lookup result inside a loop body without a nil-check fires HZN2500.
// The lookup is outside the loop; the deref is inside.
//
// Equivalent to:
//
//	count := Counts.lookup(pid)
//	for i := 0; i < 4; i++ {
//	    count.seen = 1   // unguarded deref (HZN2500)
//	}
//	return 0
func TestLoopCarryDetectsUnguardedDerefInsideForBody(t *testing.T) {
	lookupCall := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "Counts"},
			Field:   "lookup",
		},
		Args: []ir.Expr{{Kind: "ident", Name: "pid"}},
	}

	countSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("count"),
		Field:   "seen",
	}

	loopBody := []ir.Statement{
		{Kind: "assign", Target: countSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
	}

	prog := lookupProg([]ir.Statement{
		// count := Counts.lookup(pid)
		{Kind: "short_var", Name: "count", Value: lookupCall},
		// for loop with unguarded deref
		forStmt(loopBody),
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2500 := countDiag(diags, "HZN2500")
	if hzn2500 != 1 {
		t.Fatalf("HZN2500 count = %d, want exactly 1 (unguarded deref inside loop should be caught once; dedup prevents duplicate emission)", hzn2500)
	}
}

// ── Step 3.6: packet header guarded use in loop (negative test) ───────────────

// TestLoopCarryAcceptsPacketHeaderUseInsideGuardedLoopBody verifies that
// reading a packet header field inside a loop body, where the header has
// already been nil-checked before the loop, produces zero HZN2600 diagnostics.
//
// Equivalent to:
//
//	eth := xdp.eth(ctx)
//	if eth == nil { return xdp.Pass }
//	for i := 0; i < 4; i++ {
//	    _ = eth.proto   // safe: guarded before loop
//	}
//	return xdp.Pass
func TestLoopCarryAcceptsPacketHeaderUseInsideGuardedLoopBody(t *testing.T) {
	ethCall := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "xdp"},
			Field:   "eth",
		},
		Args: []ir.Expr{{Kind: "ident", Name: "ctx"}},
	}

	ethProtoDeref := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("eth"),
		Field:   "proto",
	}

	xdpPassReturn := ir.Statement{
		Kind: "return",
		Value: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "xdp"},
			Field:   "Pass",
		},
	}

	loopBody := []ir.Statement{
		// _ = eth.proto
		{Kind: "assign", Target: &ir.Expr{Kind: "ident", Name: "_"}, Value: ethProtoDeref},
	}

	prog := xdpProg([]ir.Statement{
		// eth := xdp.eth(ctx)
		{Kind: "short_var", Name: "eth", Value: ethCall},
		// if eth == nil { return xdp.Pass }
		{Kind: "if", Cond: eqNilCond("eth"), Then: []ir.Statement{xdpPassReturn}},
		// for loop with safe deref
		forStmt(loopBody),
		xdpPassReturn,
	})

	diags := validate.Program(prog)
	for _, d := range diags {
		if d.Code == "HZN2600" {
			t.Errorf("unexpected HZN2600: %s (pre-loop nil-check should protect use inside loop body)", d.Message)
		}
	}
}
