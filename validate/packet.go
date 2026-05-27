package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

// AnalyzePacket runs the packet validator's rule logic over pre-collected sites.
// The nil-check state machine (maybe_nil → nil/live) requires branch-merging
// control-flow context that Sites does not expose; validateXDPPacketHeaders is
// retained for the per-function re-walk. sites.PacketHeader is used as the
// index to avoid iterating all program functions — only XDP functions that hold
// at least one packet-header site are analyzed.
//
// effects is the program-level user-helper effect summary built once by
// validate.Program (Phase 2 #13). When a tracked packet header is passed to a
// user helper, applyHelperEffectPacket consults this summary to decide whether
// to widen the caller's state to `escaped`. For packet headers the load-bearing
// case is Preserves: a helper that does not consume the header should NOT
// suppress the caller's deref check. Consumes/Mixed at the caller side are
// indistinguishable from Preserves for the packet-header state machine — the
// caller still has to nil-check before its own field access because packet
// headers are not "owned" the way ringbuf reservations are.
func AnalyzePacket(program ir.Program, sites Sites, effects HelperEffects) []diag.Diagnostic {
	// Use sites.PacketHeader as the index: only functions that hold at least one
	// packet header site need nil-check state-machine analysis. Deduplicate by
	// function pointer; the function's section kind is already guaranteed to be
	// XDP (xdpPacketHeaderCall only matches xdp.* calls).
	var diags []diag.Diagnostic
	seen := map[*ir.Function]bool{}
	for _, site := range sites.PacketHeader {
		if seen[site.Function] {
			continue
		}
		seen[site.Function] = true
		diags = append(diags, validateXDPPacketHeaders(*site.Function, effects)...)
	}
	return diags
}

type packetHeaderState struct {
	Helper string
	State  string
}

func validateXDPPacketHeaders(fn ir.Function, effects HelperEffects) []diag.Diagnostic {
	states := map[string]packetHeaderState{}
	aliases := newAliasGraph()
	reported := map[string]bool{}
	var diags []diag.Diagnostic
	reportDeref := func(varName string, state packetHeaderState, primary span.Span) {
		key := fmt.Sprintf("%s:%d:%d", varName, primary.Start.Line, primary.Start.Column)
		if reported[key] {
			return
		}
		reported[key] = true
		switch state.State {
		case "nil":
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2601",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("nil packet header %q cannot be dereferenced", varName),
				Primary:  primary,
			})
		case "escaped":
			// escaped: resource passed to unknown function; skip deref warning.
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2600",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("packet header %q from %s must be checked against nil before dereference", varName, state.Helper),
				Primary:  primary,
				Suggest:  fmt.Sprintf("guard %s with `if %s == nil { return xdp.Pass }` before reading fields", varName, varName),
			})
		}
	}
	var checkExpr func(*ir.Expr)
	checkExpr = func(expr *ir.Expr) {
		if expr == nil {
			return
		}
		if expr.Kind == "selector" {
			// #6: prefer the field-store root if a field edge was registered for
			// this selector; otherwise fall back to the ident-base path.
			if root := aliases.rootOfSelector(expr); root != "" {
				if state, ok := states[root]; ok && state.State != "live" {
					reportDeref(root, state, expr.Span)
				}
			} else if varName, ok := selectorBase(expr); ok {
				root := aliases.root(varName)
				if state, ok := states[root]; ok && state.State != "live" {
					reportDeref(root, state, expr.Span)
				}
			}
		}
		checkExpr(expr.Operand)
		checkExpr(expr.Left)
		checkExpr(expr.Right)
		checkExpr(expr.Func)
		for i := range expr.Args {
			checkExpr(&expr.Args[i])
		}
		for i := range expr.Fields {
			checkExpr(&expr.Fields[i].Value)
		}
	}
	var walk func([]ir.Statement)
	walk = func(stmts []ir.Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var", "var_decl":
				checkExpr(stmt.Value)
				if stmt.Kind == "short_var" {
					if helper, ok := xdpPacketHeaderCall(stmt.Value); ok {
						states[stmt.Name] = packetHeaderState{Helper: helper, State: "maybe_nil"}
					}
					// Register alias if the RHS is a plain ident of an already-tracked name.
					if src := aliasOf(stmt); src != "" {
						if _, ok := states[aliases.root(src)]; ok {
							aliases.register(stmt.Name, src)
						}
					}
				}
			case "assign":
				checkExpr(stmt.Target)
				checkExpr(stmt.Value)
				// #6 field-store aliasing: register `container.slot = eth` so
				// later selector reads (`container.slot`) resolve through the
				// field edge back to eth's root. Only fires when RHS is an
				// ident of an already-tracked name; integer/literal stores
				// leave the graph alone.
				if stmt.Target != nil && stmt.Target.Kind == "selector" &&
					stmt.Target.Operand != nil && stmt.Target.Operand.Kind == "ident" &&
					stmt.Value != nil && stmt.Value.Kind == "ident" {
					src := stmt.Value.Name
					if _, ok := states[aliases.root(src)]; ok {
						aliases.registerFieldStore(stmt.Target.Operand.Name, stmt.Target.Field, src)
					}
				}
			case "expr":
				checkExpr(stmt.Expr)
				// Apply the user-helper effect summary to the call's args.
				// For packet headers, Preserves is the load-bearing case —
				// it stops the Phase 1 over-suppression that turned
				// `maybe_nil` → `escaped` on any call, silencing the
				// caller's downstream deref check. Consumes / Mixed at the
				// caller side do not change state for packet headers (the
				// caller still needs its own nil-check before its own
				// field access). Escapes / Unknown fall back to Phase 1
				// behavior.
				applyHelperEffectPacket(stmt.Expr, states, aliases, effects)
			case "return":
				checkExpr(stmt.Value)
			case "if":
				outerStates := states
				scoped := stmt.Init != nil
				if scoped {
					states = clonePacketHeaderStates(outerStates)
					walk([]ir.Statement{*stmt.Init})
				}
				func() {
					checkExpr(stmt.Cond)
					if eqVars := nilCheckedVars(stmt.Cond); len(eqVars) > 0 {
						branchStates := clonePacketHeaderStates(states)
						for _, varName := range eqVars {
							root := aliases.root(varName)
							if state, ok := branchStates[root]; ok && state.State == "maybe_nil" {
								state.State = "nil"
								branchStates[root] = state
							}
						}
						oldStates := states
						states = branchStates
						walk(stmt.Then)
						thenStates := states
						states = oldStates
						if len(stmt.Else) > 0 {
							elseStates := clonePacketHeaderStates(oldStates)
							for _, varName := range eqVars {
								root := aliases.root(varName)
								if state, ok := elseStates[root]; ok && state.State == "maybe_nil" {
									state.State = "live"
									elseStates[root] = state
								}
							}
							states = elseStates
							walk(stmt.Else)
							elseStates = states
							states = mergePacketBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
							return
						}
						if branchAlwaysReturns(stmt.Then) {
							for _, varName := range eqVars {
								root := aliases.root(varName)
								if state, ok := states[root]; ok && state.State == "maybe_nil" {
									state.State = "live"
									states[root] = state
								}
							}
						}
						return
					}
					if neqVars := nilComparedVars(stmt.Cond, "!="); len(neqVars) > 0 {
						branchStates := clonePacketHeaderStates(states)
						for _, varName := range neqVars {
							root := aliases.root(varName)
							if state, ok := branchStates[root]; ok && state.State == "maybe_nil" {
								state.State = "live"
								branchStates[root] = state
							}
						}
						oldStates := states
						states = branchStates
						walk(stmt.Then)
						thenStates := states
						states = oldStates
						if len(stmt.Else) > 0 {
							elseStates := clonePacketHeaderStates(oldStates)
							for _, varName := range neqVars {
								root := aliases.root(varName)
								if state, ok := elseStates[root]; ok && state.State == "maybe_nil" {
									state.State = "nil"
									elseStates[root] = state
								}
							}
							states = elseStates
							walk(stmt.Else)
							elseStates = states
							states = mergePacketBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
							return
						}
						return
					}
					oldStates := states
					states = clonePacketHeaderStates(oldStates)
					walk(stmt.Then)
					thenStates := states
					elseStates := oldStates
					if len(stmt.Else) > 0 {
						states = clonePacketHeaderStates(oldStates)
						walk(stmt.Else)
						elseStates = states
					}
					states = mergePacketBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
				}()
				if scoped {
					states = pruneNewPacketHeaderStates(states, outerStates)
				}
			case "switch":
				checkExpr(stmt.Value)
				oldStates := states
				mergedStates := map[string]packetHeaderState{}
				mergedReturns := false
				haveBranch := false
				hasDefault := false
				mergeBranch := func(branchStates map[string]packetHeaderState, returns bool) {
					if !haveBranch {
						mergedStates = clonePacketHeaderStates(branchStates)
						mergedReturns = returns
						haveBranch = true
						return
					}
					mergedStates = mergePacketBranchStates(mergedStates, branchStates, mergedReturns, returns)
					mergedReturns = mergedReturns && returns
				}
				for _, c := range stmt.Cases {
					for i := range c.Values {
						checkExpr(&c.Values[i])
					}
					if c.Default {
						hasDefault = true
					}
					states = clonePacketHeaderStates(oldStates)
					walk(c.Body)
					mergeBranch(states, branchAlwaysReturns(c.Body))
				}
				if !hasDefault {
					mergeBranch(oldStates, false)
				}
				states = mergedStates
			case "for":
				// Bounded 2-iteration walk for loop-carry state soundness (#5).
				// The packet-header lattice (nil → maybe_nil → guarded) has height 2
				// and a provably monotone join (lub), so two iterations are sufficient
				// — iter-3 is always identical to iter-2 for any reachable transition.
				// Walking the body once misses unguarded packet-header derefs on
				// iteration 2+ when the header state is still maybe_nil entering the loop.
				// Range-over and for {} not modeled; HZN2200 rejects for {}.
				if stmt.Init != nil {
					walk([]ir.Statement{*stmt.Init})
				}
				checkExpr(stmt.Cond)
				if stmt.Post != nil {
					walk([]ir.Statement{*stmt.Post})
				}
				// Iteration 1: snapshot pre-loop state, walk body.
				savedStates := clonePacketHeaderStates(states)
				walk(stmt.Body)
				afterIter1 := clonePacketHeaderStates(states)
				// Merge pre-loop + post-iter-1 → may-have-iterated state.
				mayHaveIterated := mergePacketBranchStates(savedStates, afterIter1, false, false)
				// Iteration 2: walk body again; diagnostics here catch cross-iteration issues.
				states = mayHaveIterated
				walk(stmt.Body)
				afterIter2 := clonePacketHeaderStates(states)
				// Post-loop state: merge iter-1 and iter-2 outcomes.
				states = mergePacketBranchStates(afterIter1, afterIter2, false, false)
			}
		}
	}
	walk(functionStatements(fn))
	return diags
}

// applyHelperEffectPacket transitions caller-side packet-header state at
// every call site, consulting the program-level HelperEffects summary.
//
// For packet headers, the Phase 1 rule was: any non-live header state passed
// to ANY call widens to "escaped" — including `maybe_nil`, which over-
// suppressed the caller's downstream deref check (HZN2600). This is the
// load-bearing regression Task 6 fixes.
//
// Per-call-site behavior:
//
//  1. User-helper call (bare-ident callee): per arg, consult
//     effects.EffectFor(name, i):
//     - Preserves → state unchanged (the load-bearing case — stops over-
//       suppression so the caller's deref check still fires).
//     - Consumes  → state unchanged. Packet headers are not "owned" the
//       way ringbuf reservations are; the helper's internal deref does
//       not absolve the caller of its own nil-check. Indistinguishable
//       from Preserves at the caller side today; the distinction is kept
//       on the summary side because v0.3 may use it differently.
//     - Mixed     → state unchanged. Same reasoning as Consumes.
//     - Escapes / Unknown → Phase 1 fallback: any non-live state widens
//       to "escaped".
//
//  2. Any other call (compiler-known helper like xdp.eth, or a selector
//     form that isn't a known helper): fall back to Phase 1 escape — any
//     non-live state widens to "escaped". This preserves the conservative
//     behavior for call sites we cannot precisely classify.
//
// The function recurses into Args so nested calls (f(g(eth))) are processed
// in lexical order — g's effect on eth applies before f's.
//
// NOTE: packet preserves the Phase 1 asymmetry vs ringbuf — escape applies
// to ANY non-live state (including `maybe_nil`), not just `live`. The
// fallback gate is `state.State != "live" && state.State != "escaped"`,
// matching pre-Task-6 behavior for unanalyzable calls.
func applyHelperEffectPacket(expr *ir.Expr, states map[string]packetHeaderState, aliases *aliasGraph, effects HelperEffects) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		helperName := userHelperName(expr.Func)
		for i := range expr.Args {
			arg := &expr.Args[i]
			// Recurse into the arg FIRST so nested calls classify their
			// effect on the arg before the outer call.
			applyHelperEffectPacket(arg, states, aliases, effects)
			if arg.Kind != "ident" {
				continue
			}
			root := aliases.root(arg.Name)
			state, ok := states[root]
			if !ok {
				continue
			}
			if helperName != "" {
				switch effects.EffectFor(helperName, i) {
				case HelperEffectPreserves, HelperEffectConsumes, HelperEffectMixed:
					// State unchanged — for packet headers, the caller
					// still owes a nil-check before its own field access
					// regardless of what the helper did internally.
				default:
					// HelperEffectEscapes or HelperEffectUnknown: fall
					// back to Phase 1 "any non-live → escaped".
					if state.State != "live" && state.State != "escaped" {
						state.State = "escaped"
						states[root] = state
					}
				}
				continue
			}
			// Non-user-helper call site (selector form): Phase 1 fallback.
			if state.State != "live" && state.State != "escaped" {
				state.State = "escaped"
				states[root] = state
			}
		}
	}
	applyHelperEffectPacket(expr.Operand, states, aliases, effects)
	applyHelperEffectPacket(expr.Left, states, aliases, effects)
	applyHelperEffectPacket(expr.Right, states, aliases, effects)
	applyHelperEffectPacket(expr.Func, states, aliases, effects)
}

func xdpPacketHeaderCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" {
		return "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || operand.Kind != "ident" || operand.Name != "xdp" {
		return "", false
	}
	switch method {
	case "eth", "ipv4", "tcp", "udp":
		return "xdp." + method, true
	default:
		return "", false
	}
}

func clonePacketHeaderStates(in map[string]packetHeaderState) map[string]packetHeaderState {
	out := make(map[string]packetHeaderState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pruneNewPacketHeaderStates(in map[string]packetHeaderState, outer map[string]packetHeaderState) map[string]packetHeaderState {
	out := clonePacketHeaderStates(in)
	for name := range out {
		if _, ok := outer[name]; !ok {
			delete(out, name)
		}
	}
	return out
}

func mergePacketBranchStates(thenStates map[string]packetHeaderState, elseStates map[string]packetHeaderState, thenReturns bool, elseReturns bool) map[string]packetHeaderState {
	switch {
	case thenReturns && elseReturns:
		return map[string]packetHeaderState{}
	case thenReturns:
		return clonePacketHeaderStates(elseStates)
	case elseReturns:
		return clonePacketHeaderStates(thenStates)
	}

	out := clonePacketHeaderStates(thenStates)
	for name, elseState := range elseStates {
		thenState, ok := out[name]
		if !ok {
			out[name] = elseState
			continue
		}
		out[name] = mergePacketHeaderState(thenState, elseState)
	}
	return out
}

func mergePacketHeaderState(a packetHeaderState, b packetHeaderState) packetHeaderState {
	if a.Helper == "" {
		return b
	}
	if b.Helper == "" {
		return a
	}
	return packetHeaderState{
		Helper: a.Helper,
		State:  mergeNilPromotionState(a.State, b.State),
	}
}
