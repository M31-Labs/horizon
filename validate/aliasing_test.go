// Package validate_test exercises the intra-function alias graph that was
// added in Phase 1 Track A Task 1 (#1 aliasing/escape).
//
// All tests use synthetic in-memory ir.Program fixtures. Real .hzn source
// programs cannot exercise these paths today because HZN1447 in types/checker.go
// rejects aliased variable references at the source level. The validate-layer
// machinery is built now so that when Phase 2 #13 (maple) relaxes HZN1447 for
// helper-arg passes, the state machine substrate is ready.
//
// Debt (per plan Q2): if cedar's Track B lands a partial HZN1447 relaxation
// early, revisit whether end-to-end .hzn fixtures are preferable. Default: synthetic.
package validate_test

import (
	"testing"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// ── Fixture helpers ────────────────────────────────────────────────────────────

// reserveExpr builds: Events.reserve()
func reserveExpr(mapName string) *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: mapName},
			Field:   "reserve",
		},
	}
}

// submitExpr builds: Events.submit(varName)
func submitExpr(mapName, varName string) *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: mapName},
			Field:   "submit",
		},
		Args: []ir.Expr{{Kind: "ident", Name: varName}},
	}
}

// nilExpr builds the nil literal.
func nilExpr() *ir.Expr {
	return &ir.Expr{Kind: "nil"}
}

// identExpr builds an identifier expression.
func identExpr(name string) *ir.Expr {
	return &ir.Expr{Kind: "ident", Name: name}
}

// eqNilCond builds: varName == nil
func eqNilCond(varName string) *ir.Expr {
	return &ir.Expr{
		Kind:  "binary",
		Op:    "==",
		Left:  identExpr(varName),
		Right: nilExpr(),
	}
}

// neqNilCond builds: varName != nil
func neqNilCond(varName string) *ir.Expr {
	return &ir.Expr{
		Kind:  "binary",
		Op:    "!=",
		Left:  identExpr(varName),
		Right: nilExpr(),
	}
}

// returnZero builds: return 0
func returnZero() ir.Statement {
	return ir.Statement{Kind: "return", Value: &ir.Expr{Kind: "int", Value: "0"}}
}

// shortVarIdent builds: name := src  (ident copy)
func shortVarIdent(name, src string) ir.Statement {
	return ir.Statement{
		Kind:  "short_var",
		Name:  name,
		Value: identExpr(src),
	}
}

// exprStmt wraps an expression as a statement.
func exprStmt(expr *ir.Expr) ir.Statement {
	return ir.Statement{Kind: "expr", Expr: expr}
}

// ringbufProg builds a minimal ir.Program with a ringbuf map named "Events"
// and a single tracepoint function whose body is the given statements.
func ringbufProg(stmts []ir.Statement) ir.Program {
	return ir.Program{
		Maps: []ir.Map{{Name: "Events", Kind: ir.MapKindRingbuf, Val: ir.Type{Name: "Event"}}},
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_exec"},
			Body:    []ir.Block{{Statements: stmts}},
		}},
	}
}

// lookupProg builds a minimal ir.Program with a hash map named "Counts"
// and a single tracepoint function whose body is the given statements.
func lookupProg(stmts []ir.Statement) ir.Program {
	return ir.Program{
		Maps: []ir.Map{{
			Name: "Counts",
			Kind: ir.MapKindHash,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "u64"},
		}},
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_exec"},
			Body:    []ir.Block{{Statements: stmts}},
		}},
	}
}

// xdpProg builds a minimal ir.Program with a single XDP function whose body
// is the given statements.
func xdpProg(stmts []ir.Statement) ir.Program {
	return ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramXDP, Name: "xdp"},
			Body:    []ir.Block{{Statements: stmts}},
		}},
	}
}

// countDiag returns the number of diagnostics with the given code.
func countDiag(diags []diag.Diagnostic, code string) int {
	n := 0
	for _, d := range diags {
		if d.Code == code {
			n++
		}
	}
	return n
}

// ── Step 1.2: alias via short_var copy (ringbuf) ───────────────────────────────

// buildAliasReserveProgram constructs the IR equivalent of:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	alias := event
//	// never submitted via alias OR event
//	return 0
func buildAliasReserveProgram() ir.Program {
	return ringbufProg([]ir.Statement{
		// event := Events.reserve()
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		// if event == nil { return 0 }
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		// alias := event
		shortVarIdent("alias", "event"),
		// return 0  (live on return — should fire HZN2104 once, not twice)
		returnZero(),
	})
}

// TestAliasingPropagatesRingbufStateThroughShortVarCopy verifies that when
// `alias := event` is present and neither name is ever submitted, HZN2104
// fires exactly once (alias collapsed to its root; not double-reported).
func TestAliasingPropagatesRingbufStateThroughShortVarCopy(t *testing.T) {
	prog := buildAliasReserveProgram()
	diags := validate.Program(prog)
	hzn2104 := countDiag(diags, "HZN2104")
	if hzn2104 != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (alias should not double-report)", hzn2104)
	}
}

// ── Step 1.6: alias for map lookup deref ──────────────────────────────────────

// buildAliasMapsProgram constructs the IR equivalent of:
//
//	count := Counts.lookup(pid)
//	alias := count
//	alias.seen = 1   // unguarded dereference on alias of unguarded lookup
//	return 0
func buildAliasMapsProgram() ir.Program {
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
	// alias.seen  (selector expression used as assignment target)
	aliasSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("alias"),
		Field:   "seen",
	}
	return lookupProg([]ir.Statement{
		{Kind: "short_var", Name: "count", Value: lookupCall},
		shortVarIdent("alias", "count"),
		// alias.seen = 1
		{Kind: "assign", Target: aliasSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
		returnZero(),
	})
}

// TestAliasingPropagatesMapLookupNilStateThroughShortVarCopy verifies that
// when `alias := count` is present and `alias.seen` is dereferenced without a
// nil-check, HZN2500 fires exactly once (alias resolved to root `count`).
func TestAliasingPropagatesMapLookupNilStateThroughShortVarCopy(t *testing.T) {
	prog := buildAliasMapsProgram()
	diags := validate.Program(prog)
	hzn2500 := countDiag(diags, "HZN2500")
	if hzn2500 != 1 {
		t.Fatalf("HZN2500 count = %d, want 1 (alias should not double-report)", hzn2500)
	}
}

// ── Step 1.8: alias for packet header ─────────────────────────────────────────

// buildAliasPacketProgram constructs the IR equivalent of:
//
//	eth := xdp.eth(ctx)
//	alias := eth
//	if alias.proto == 0 { return xdp.Drop }   // dereference before nil-check
//	return xdp.Pass
func buildAliasPacketProgram() ir.Program {
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
	// alias.proto (selector that triggers the nil check)
	aliasProto := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("alias"),
		Field:   "proto",
	}
	// if alias.proto == 0 { return xdp.Drop }
	ifStmt := ir.Statement{
		Kind: "if",
		Cond: &ir.Expr{
			Kind:  "binary",
			Op:    "==",
			Left:  aliasProto,
			Right: &ir.Expr{Kind: "int", Value: "0"},
		},
		Then: []ir.Statement{returnZero()},
	}
	return xdpProg([]ir.Statement{
		{Kind: "short_var", Name: "eth", Value: ethCall},
		shortVarIdent("alias", "eth"),
		ifStmt,
		returnZero(),
	})
}

// TestAliasingPropagatesPacketHeaderNilStateThroughShortVarCopy verifies that
// when `alias := eth` is present and `alias.proto` is accessed without a
// nil-check, HZN2600 fires exactly once.
func TestAliasingPropagatesPacketHeaderNilStateThroughShortVarCopy(t *testing.T) {
	prog := buildAliasPacketProgram()
	diags := validate.Program(prog)
	hzn2600 := countDiag(diags, "HZN2600")
	if hzn2600 != 1 {
		t.Fatalf("HZN2600 count = %d, want 1 (alias should not double-report)", hzn2600)
	}
}

// ── Step 1.10: nil-check on ALIAS name promotes root state ────────────────────

// buildAliasNilCheckProgram constructs the IR equivalent of:
//
//	event := Events.reserve()
//	alias := event
//	if alias == nil { return 0 }
//	Events.submit(alias)   // alias nil-checked → root event is live → submit OK
//	return 0
func buildAliasNilCheckProgram() ir.Program {
	return ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		shortVarIdent("alias", "event"),
		// if alias == nil { return 0 }  — this nil-check promotes event's root
		{Kind: "if", Cond: eqNilCond("alias"), Then: []ir.Statement{returnZero()}},
		// Events.submit(alias)  — alias is now live (resolved to event)
		exprStmt(submitExpr("Events", "alias")),
		returnZero(),
	})
}

// TestAliasingPromotesStateWhenAliasIsNilChecked verifies that nil-checking
// `alias` promotes the state of the root `event`, so submitting via `alias`
// inside the guarded branch produces zero diagnostics.
func TestAliasingPromotesStateWhenAliasIsNilChecked(t *testing.T) {
	prog := buildAliasNilCheckProgram()
	diags := validate.Program(prog)
	if len(diags) != 0 {
		codes := make([]string, len(diags))
		for i, d := range diags {
			codes[i] = d.Code
		}
		t.Fatalf("expected 0 diagnostics, got %d: %v", len(diags), codes)
	}
}

// ── Step 1.14: escape via call argument ───────────────────────────────────────

// buildEscapeProg constructs the IR equivalent of:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	unknownHelper(event)
//	return 0
func buildEscapeProg() ir.Program {
	// unknownHelper(event)
	unknownCall := &ir.Expr{
		Kind: "call",
		Func: identExpr("unknownHelper"),
		Args: []ir.Expr{{Kind: "ident", Name: "event"}},
	}
	return ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		exprStmt(unknownCall),
		returnZero(),
	})
}

// TestEscapeMarksReservationAsLiveWhenPassedToUnknownFunction verifies that
// passing a live ringbuf reservation to an unknown function transitions its
// state to "escaped", suppressing HZN2104 on return. We cannot prove whether
// the helper consumed the reservation; the conservative call is to not fire
// a false positive.
func TestEscapeMarksReservationAsLiveWhenPassedToUnknownFunction(t *testing.T) {
	prog := buildEscapeProg()
	diags := validate.Program(prog)
	hzn2104 := countDiag(diags, "HZN2104")
	if hzn2104 != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (escaped resource should not fire live-on-return)", hzn2104)
	}
}

// ── Iteration 2 fix: escape dominates in branch merge (maps) ────────────────────

// buildEscapeDominatesMapsProgram constructs the IR equivalent of:
//
//	count := Counts.lookup(pid)
//	if pid > 0 {
//	  unknownHelper(count)  // one branch escapes count
//	}
//	// other branch does nothing
//	// after merge, dereference count
//	count.seen = 1
//	return 0
//
// If mergeNilPromotionState does not make "escaped" dominant, the merge
// would incorrectly return "maybe_nil", causing HZN2500 to fire.
// Correct behavior: merged state is "escaped", HZN2500 does not fire.
func buildEscapeDominatesMapsProgram() ir.Program {
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
	// unknownHelper(count)
	unknownCall := &ir.Expr{
		Kind: "call",
		Func: identExpr("unknownHelper"),
		Args: []ir.Expr{{Kind: "ident", Name: "count"}},
	}
	// count.seen (selector used as assignment target)
	countSeen := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("count"),
		Field:   "seen",
	}
	return lookupProg([]ir.Statement{
		{Kind: "short_var", Name: "count", Value: lookupCall},
		// if pid > 0 { unknownHelper(count) }
		{
			Kind: "if",
			Cond: &ir.Expr{
				Kind:  "binary",
				Op:    ">",
				Left:  identExpr("pid"),
				Right: &ir.Expr{Kind: "int", Value: "0"},
			},
			Then: []ir.Statement{exprStmt(unknownCall)},
			Else: []ir.Statement{}, // other branch does nothing
		},
		// count.seen = 1  (after merge)
		{Kind: "assign", Target: countSeen, Value: &ir.Expr{Kind: "int", Value: "1"}},
		returnZero(),
	})
}

// TestEscapeDominatesBranchMergeForMapLookup verifies that when one branch
// escapes a map lookup result and the other branch does nothing, the merged
// state is "escaped" (not "maybe_nil"). This prevents false-positive HZN2500
// warnings on a resource we can no longer trust.
func TestEscapeDominatesBranchMergeForMapLookup(t *testing.T) {
	prog := buildEscapeDominatesMapsProgram()
	diags := validate.Program(prog)
	hzn2500 := countDiag(diags, "HZN2500")
	if hzn2500 != 0 {
		t.Fatalf("HZN2500 count = %d, want 0 (escaped state should dominate branch merge)", hzn2500)
	}
}

// ── Iteration 2 fix: escape dominates in branch merge (packet) ────────────────────

// buildEscapeDominatesPacketProgram constructs the IR equivalent of:
//
//	eth := xdp.eth(ctx)
//	if ctx != 0 {
//	  unknownHelper(eth)  // one branch escapes eth
//	}
//	// other branch does nothing
//	// after merge, dereference eth
//	if eth.proto == 0 { return xdp.Drop }
//	return xdp.Pass
//
// If mergeNilPromotionState does not make "escaped" dominant, the merge
// would incorrectly return "maybe_nil", causing HZN2600 to fire.
// Correct behavior: merged state is "escaped", HZN2600 does not fire.
func buildEscapeDominatesPacketProgram() ir.Program {
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
	// unknownHelper(eth)
	unknownCall := &ir.Expr{
		Kind: "call",
		Func: identExpr("unknownHelper"),
		Args: []ir.Expr{{Kind: "ident", Name: "eth"}},
	}
	// eth.proto (selector that triggers the nil check)
	ethProto := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("eth"),
		Field:   "proto",
	}
	return xdpProg([]ir.Statement{
		{Kind: "short_var", Name: "eth", Value: ethCall},
		// if ctx != 0 { unknownHelper(eth) }
		{
			Kind: "if",
			Cond: &ir.Expr{
				Kind:  "binary",
				Op:    "!=",
				Left:  identExpr("ctx"),
				Right: &ir.Expr{Kind: "int", Value: "0"},
			},
			Then: []ir.Statement{exprStmt(unknownCall)},
			Else: []ir.Statement{}, // other branch does nothing
		},
		// if eth.proto == 0 { return 0 }  (after merge)
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
	})
}

// TestEscapeDominatesBranchMergeForPacketHeader verifies that when one branch
// escapes a packet header result and the other branch does nothing, the merged
// state is "escaped" (not "maybe_nil"). This prevents false-positive HZN2600
// warnings on a resource we can no longer trust.
func TestEscapeDominatesBranchMergeForPacketHeader(t *testing.T) {
	prog := buildEscapeDominatesPacketProgram()
	diags := validate.Program(prog)
	hzn2600 := countDiag(diags, "HZN2600")
	if hzn2600 != 0 {
		t.Fatalf("HZN2600 count = %d, want 0 (escaped state should dominate branch merge)", hzn2600)
	}
}

// ── #6 (B2) struct-field aliasing — intra-function graph extension ────────────
//
// The next three tests pin the field-store edges added to aliasGraph for #6.
// Each constructs synthetic IR; .hzn source cannot reach these shapes today
// because HZN1447 (statement-level alias guard in types/checker.go) rejects
// any `event.alias = x` style assignment whose RHS is a tracked pointer.
// The substrate landing covers (i) future relaxations of HZN1447 inside helper
// bodies and (ii) IR-construction paths that synthesize selector stores.

// buildAliasFieldStoreProgram constructs the IR equivalent of:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	container.slot = event   // field-store of tracked resource
//	return 0                  // live on return — exactly ONE HZN2104 expected
//
// Pre-Task-3 the field store was a no-op for the alias graph; the validator
// still produced exactly one HZN2104 for `event`. Post-Task-3 the field-store
// edge MUST NOT introduce a second tracked entry that double-reports — the
// rootOfSelector resolution collapses container.slot back onto event's root.
func buildAliasFieldStoreProgram() ir.Program {
	containerSlot := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("container"),
		Field:   "slot",
	}
	return ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		// container.slot = event
		{Kind: "assign", Target: containerSlot, Value: identExpr("event")},
		returnZero(),
	})
}

// TestAliasingPropagatesRingbufStateThroughFieldStore pins that storing a
// tracked ringbuf reservation into a struct field collapses to the same root
// (one HZN2104, not two) and never creates a spurious second tracked entry
// for `container.slot`.
func TestAliasingPropagatesRingbufStateThroughFieldStore(t *testing.T) {
	prog := buildAliasFieldStoreProgram()
	diags := validate.Program(prog)
	hzn2104 := countDiag(diags, "HZN2104")
	if hzn2104 != 1 {
		t.Fatalf("HZN2104 count = %d, want 1 (field-store alias must not double-report)", hzn2104)
	}
}

// buildAliasFieldRebindThenSubmitProgram constructs the IR equivalent of:
//
//	event := Events.reserve()
//	if event == nil { return 0 }
//	container.slot = event
//	Events.submit(container.slot)   // submit via the field-aliased name
//	return 0
//
// The submit's argument is a selector, not a bare ident. Without rootOfSelector
// wired into the consume-call resolver, the submit reads as unclassified, event
// stays "live", and HZN2104 fires on return. Post-Task-3 the field-store edge
// rooted at `event` lets the submit consume the underlying reservation.
func buildAliasFieldRebindThenSubmitProgram() ir.Program {
	containerSlot := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("container"),
		Field:   "slot",
	}
	submitSelector := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: identExpr("Events"),
			Field:   "submit",
		},
		Args: []ir.Expr{*containerSlot},
	}
	return ringbufProg([]ir.Statement{
		{Kind: "short_var", Name: "event", Value: reserveExpr("Events")},
		{Kind: "if", Cond: eqNilCond("event"), Then: []ir.Statement{returnZero()}},
		{Kind: "assign", Target: containerSlot, Value: identExpr("event")},
		exprStmt(submitSelector),
		returnZero(),
	})
}

// TestAliasingFieldRebindDoesNotLoseTracking pins that submitting via the
// field-aliased selector (`Events.submit(container.slot)`) successfully
// consumes the underlying tracked reservation — no HZN2104 should fire.
func TestAliasingFieldRebindDoesNotLoseTracking(t *testing.T) {
	prog := buildAliasFieldRebindThenSubmitProgram()
	diags := validate.Program(prog)
	hzn2104 := countDiag(diags, "HZN2104")
	if hzn2104 != 0 {
		t.Fatalf("HZN2104 count = %d, want 0 (submit via field-alias must consume root)", hzn2104)
	}
}

// buildAliasFieldStoreOfNonResourceProgram constructs the IR equivalent of:
//
//	container.slot = 42   // pure integer store — no tracked resources at all
//	return 0
//
// The field-store edge must NOT fire for non-tracked RHS. Otherwise we would
// silently shadow legitimate integer field writes with a spurious alias edge,
// breaking later analysis. Assertion: zero diagnostics on this fixture.
func buildAliasFieldStoreOfNonResourceProgram() ir.Program {
	containerSlot := &ir.Expr{
		Kind:    "selector",
		Operand: identExpr("container"),
		Field:   "slot",
	}
	return ringbufProg([]ir.Statement{
		{Kind: "assign", Target: containerSlot, Value: &ir.Expr{Kind: "int", Value: "42"}},
		returnZero(),
	})
}

// TestAliasingFieldStoreOfNonResourceIgnored pins that an integer-valued field
// store registers no alias edge and produces no diagnostics.
func TestAliasingFieldStoreOfNonResourceIgnored(t *testing.T) {
	prog := buildAliasFieldStoreOfNonResourceProgram()
	diags := validate.Program(prog)
	if len(diags) != 0 {
		codes := make([]string, len(diags))
		for i, d := range diags {
			codes[i] = d.Code
		}
		t.Fatalf("expected 0 diagnostics, got %d: %v", len(diags), codes)
	}
}
