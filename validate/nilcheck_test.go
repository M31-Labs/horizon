// Package validate_test exercises multi-condition nil-check recognition added
// in Phase 1 Track A Task 2 (#2). All tests use synthetic in-memory ir.Program
// fixtures following the same conventions as aliasing_test.go.
package validate_test

import (
	"testing"

	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// andCond builds: left && right
func andCond(left, right *ir.Expr) *ir.Expr {
	return &ir.Expr{
		Kind:  "binary",
		Op:    "&&",
		Left:  left,
		Right: right,
	}
}

// orCond builds: left || right
func orCond(left, right *ir.Expr) *ir.Expr {
	return &ir.Expr{
		Kind:  "binary",
		Op:    "||",
		Left:  left,
		Right: right,
	}
}

// intGtCond builds: varName > value (generic non-nil comparison)
func intGtCond(varName string, value string) *ir.Expr {
	return &ir.Expr{
		Kind:  "binary",
		Op:    ">",
		Left:  identExpr(varName),
		Right: &ir.Expr{Kind: "int", Value: value},
	}
}

// ── Step 2.2: ringbuf &&-conjunction test ─────────────────────────────────────

// TestNilCheckRecognizedInAndConjunction verifies that
//
//	event := Events.reserve()
//	if event != nil && pid > 0 {
//	    Events.submit(event)
//	}
//	return 0
//
// produces zero HZN2100 diagnostics. The `&&` condition should promote `event`
// to "live" in the then-arm even though the nil-check is not the sole operand.
func TestNilCheckRecognizedInAndConjunction(t *testing.T) {
	prog := ringbufProg([]ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event != nil && pid > 0 { Events.submit(event) }
		{
			Kind: "if",
			Cond: andCond(neqNilCond("event"), intGtCond("pid", "0")),
			Then: []ir.Statement{exprStmt(submitExpr("Events", "event"))},
		},
		// return 0
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	if hzn2100 != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (&&-conjunction nil-check should promote event to live)", hzn2100)
	}
}

// ── Step 2.6: maps &&-conjunction test ────────────────────────────────────────

// TestMapsNilCheckRecognizedInAndConjunction verifies that
//
//	count := Counts.lookup(pid)
//	if count != nil && pid > 0 {
//	    count.seen = 1
//	}
//	return 0
//
// produces zero HZN2500 diagnostics. The `&&` condition should promote `count`
// to "live" in the then-arm.
func TestMapsNilCheckRecognizedInAndConjunction(t *testing.T) {
	// count := Counts.lookup(pid)
	lookupCall := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "Counts"},
			Field:   "lookup",
		},
		Args: []ir.Expr{{Kind: "ident", Name: "pid"}},
	}
	// count.seen (selector for assignment target)
	countSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("count"),
		Field:   "seen",
	}

	prog := lookupProg([]ir.Statement{
		// count := Counts.lookup(pid)
		{Kind: "short_var", Name: "count", Value: lookupCall},
		// if count != nil && pid > 0 { count.seen = 1 }
		{
			Kind: "if",
			Cond: andCond(neqNilCond("count"), intGtCond("pid", "0")),
			Then: []ir.Statement{
				{Kind: "assign", Target: countSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
			},
		},
		// return 0
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2500 := countDiag(diags, "HZN2500")
	if hzn2500 != 0 {
		t.Fatalf("HZN2500 count = %d, want 0 (&&-conjunction nil-check should promote count to live)", hzn2500)
	}
}

// TestPacketNilCheckRecognizedInAndConjunction verifies that
//
//	eth := xdp.eth(ctx)
//	if eth != nil && pid > 0 {
//	    _ = eth.proto   // dereference inside guarded arm — safe once && promotes eth to live
//	}
//	return xdp.Pass
//
// produces zero HZN2600 diagnostics. The `&&` condition should promote `eth`
// to "live" in the then-arm so the dereference `eth.proto` is not flagged.
func TestPacketNilCheckRecognizedInAndConjunction(t *testing.T) {
	// eth := xdp.eth(ctx)
	ethCall := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "xdp"},
			Field:   "eth",
		},
		Args: []ir.Expr{{Kind: "ident", Name: "ctx"}},
	}
	// eth.proto  (dereference inside then-arm body)
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

	prog := xdpProg([]ir.Statement{
		// eth := xdp.eth(ctx)
		{Kind: "short_var", Name: "eth", Value: ethCall},
		// if eth != nil && pid > 0 { _ = eth.proto }
		{
			Kind: "if",
			Cond: andCond(neqNilCond("eth"), intGtCond("pid", "0")),
			Then: []ir.Statement{
				// assign eth.proto to blank — forces the validator to evaluate the
				// selector expression, triggering HZN2600 if eth is still maybe_nil.
				{Kind: "assign", Target: &ir.Expr{Kind: "ident", Name: "_"}, Value: ethProtoDeref},
			},
		},
		// return xdp.Pass
		xdpPassReturn,
	})

	diags := validate.Program(prog)
	hzn2600 := countDiag(diags, "HZN2600")
	if hzn2600 != 0 {
		t.Fatalf("HZN2600 count = %d, want 0 (&&-conjunction nil-check should promote eth to live)", hzn2600)
	}
}

// ── Step 2.8: || disjunction negative test ────────────────────────────────────

// notCond builds: !inner
func notCond(inner *ir.Expr) *ir.Expr {
	return &ir.Expr{
		Kind:    "unary",
		Op:      "!",
		Operand: inner,
	}
}

// ── Task 1 (#5 B1): DeMorgan / !-negation recognition tests ───────────────────

// TestNilCheckRecognizedInNegatedEquality verifies that
//
//	event := Events.reserve()
//	if !(event == nil) { Events.submit(event) }
//	return 0
//
// produces zero HZN2100 diagnostics. `!(event == nil)` is DeMorgan-equivalent
// to `event != nil`, so the then-arm should promote event to live.
func TestNilCheckRecognizedInNegatedEquality(t *testing.T) {
	prog := ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{
			Kind: "if",
			Cond: notCond(eqNilCond("event")),
			Then: []ir.Statement{exprStmt(submitExpr("Events", "event"))},
		},
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	if hzn2100 != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (!(event == nil) should promote event to live)", hzn2100)
	}
}

// TestNilCheckRecognizedInDoubleNegation verifies that
//
//	event := Events.reserve()
//	if !!(event != nil) { Events.submit(event) }
//	return 0
//
// produces zero HZN2100 diagnostics. Two consecutive `!`s cancel; `!!(event !=
// nil)` is equivalent to `event != nil`.
func TestNilCheckRecognizedInDoubleNegation(t *testing.T) {
	prog := ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{
			Kind: "if",
			Cond: notCond(notCond(neqNilCond("event"))),
			Then: []ir.Statement{exprStmt(submitExpr("Events", "event"))},
		},
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	if hzn2100 != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (!!(event != nil) should promote event to live)", hzn2100)
	}
}

// TestNilCheckRecognizedInDemorganDisjunction verifies that
//
//	a := Events.reserve()
//	b := Events.reserve()
//	if !(a == nil || b == nil) { Events.submit(a); Events.submit(b) }
//	return 0
//
// produces zero HZN2100 diagnostics. `!(a == nil || b == nil)` is DeMorgan-
// equivalent to `a != nil && b != nil`, so both reservations should promote
// to live in the then-arm.
func TestNilCheckRecognizedInDemorganDisjunction(t *testing.T) {
	prog := ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "a", Value: reserveExpr("Events")},
		{Kind: "short_var", Name: "b", Value: reserveExpr("Events")},
		{
			Kind: "if",
			Cond: notCond(orCond(eqNilCond("a"), eqNilCond("b"))),
			Then: []ir.Statement{
				exprStmt(submitExpr("Events", "a")),
				exprStmt(submitExpr("Events", "b")),
			},
		},
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	if hzn2100 != 0 {
		t.Fatalf("HZN2100 count = %d, want 0 (!(a == nil || b == nil) should promote both)", hzn2100)
	}
}

// TestNilCheckNegatedConjunctionDoesNotPromote verifies that
//
//	event := Events.reserve()
//	if !(event != nil && pid > 0) { Events.submit(event) }
//	return 0
//
// produces at least one HZN2100. `!(event != nil && pid > 0)` is DeMorgan-
// equivalent to `event == nil || pid <= 0`, so event must NOT promote to live
// in the then-arm — only one disjunct may hold.
func TestNilCheckNegatedConjunctionDoesNotPromote(t *testing.T) {
	prog := ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{
			Kind: "if",
			Cond: notCond(andCond(neqNilCond("event"), intGtCond("pid", "0"))),
			Then: []ir.Statement{exprStmt(submitExpr("Events", "event"))},
		},
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	if hzn2100 == 0 {
		t.Errorf("HZN2100 count = 0, want >= 1 (negated conjunction must NOT promote event)")
	}
}

// TestNilCheckDisjunctionDoesNotPromote verifies that
//
//	event := Events.reserve()
//	if event != nil || flag == 1 {
//	    Events.submit(event)
//	}
//	return 0
//
// produces at least one HZN2100 (unguarded submit) AND at least one HZN2104
// (live-on-return). The `||` condition must NOT promote `event` to "live" in
// the then-arm because only one disjunct may hold.
func TestNilCheckDisjunctionDoesNotPromote(t *testing.T) {
	// flag == 1
	flagCond := &ir.Expr{
		Kind:  "binary",
		Op:    "==",
		Left:  identExpr("flag"),
		Right: &ir.Expr{Kind: "int", Value: "1"},
	}

	prog := ringbufProg([]ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event != nil || flag == 1 { Events.submit(event) }
		{
			Kind: "if",
			Cond: orCond(neqNilCond("event"), flagCond),
			Then: []ir.Statement{exprStmt(submitExpr("Events", "event"))},
		},
		// return 0
		returnZero(),
	})

	diags := validate.Program(prog)
	hzn2100 := countDiag(diags, "HZN2100")
	hzn2104 := countDiag(diags, "HZN2104")
	if hzn2100 == 0 {
		t.Errorf("HZN2100 count = 0, want >= 1 (|| should NOT promote event to live; submit is unguarded)")
	}
	if hzn2104 == 0 {
		t.Errorf("HZN2104 count = 0, want >= 1 (event left live on return path when || does not promote)")
	}
}
