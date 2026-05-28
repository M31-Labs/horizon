package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

// AnalyzeRingbuf runs the ringbuf validator's rule logic over pre-collected sites.
// The state-machine analysis (maybe_nil → live → consumed) requires branch-
// merging control-flow context that Sites does not expose. sites.RingbufReserve
// is the load-bearing index of functions that hold reserve sites; the state
// machine re-walk (validateTypedRingbuf) is run only for those functions. Typed
// functions that contain no ringbuf reserves are skipped entirely — they cannot
// produce ringbuf diagnostics.
//
// effects is the program-level user-helper effect summary built once by
// validate.Program (Phase 2 #13). When a tracked reservation is passed to a
// user helper, applyHelperEffectRingbuf consults this summary to transition
// the caller's state precisely instead of falling back to "escaped". For
// programs that contain no user helpers (or for sites whose callee summary
// is Unknown/Escapes), the behavior matches Phase 1 verbatim.
func AnalyzeRingbuf(program ir.Program, sites Sites, effects HelperEffects) []diag.Diagnostic {
	ringMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf {
			ringMaps[m.Name] = m
		}
	}
	if len(ringMaps) == 0 {
		return nil
	}

	seen := map[*ir.Function]bool{}
	var diags []diag.Diagnostic
	for _, site := range sites.RingbufReserve {
		if seen[site.Function] {
			continue
		}
		seen[site.Function] = true
		diags = append(diags, validateTypedRingbuf(*site.Function, ringMaps, effects)...)
	}
	// v0.3 alder Phase 2 (roadmap #18): also walk functions that bind a user-
	// helper return value into a short_var, in case that helper's return
	// verdict (ReturnEffectReturnsResource / Maybe) means the bound name
	// becomes a tracked reservation. Walk is deduped against the set already
	// visited from RingbufReserve.
	for _, site := range sites.RingbufHelperReturn {
		if seen[site.Function] {
			continue
		}
		seen[site.Function] = true
		diags = append(diags, validateTypedRingbuf(*site.Function, ringMaps, effects)...)
	}
	return diags
}

type reserveState struct {
	Map   string
	State string
}

func validateTypedRingbuf(fn ir.Function, ringMaps map[string]ir.Map, effects HelperEffects) []diag.Diagnostic {
	states := map[string]reserveState{}
	aliases := newAliasGraph()
	reportedMissingNil := map[string]bool{}
	reportedLive := map[string]bool{}
	// reportedAt deduplicates HZN2102/HZN2103/HZN2105 diagnostics across the
	// bounded 2-iteration loop-carry walk. The same (code, span) pair may be
	// visited twice — once per iteration — so we suppress the second emission.
	reportedAt := map[string]bool{}
	var diags []diag.Diagnostic
	reportLive := func(varName string, primary span.Span) {
		root := aliases.root(varName)
		if reportedLive[root] {
			return
		}
		diags = append(diags, liveOnReturnAt(fn, root, primary))
		reportedLive[root] = true
	}
	checkWrite := func(varName string, primary span.Span) {
		root := aliases.root(varName)
		state, ok := states[root]
		if !ok {
			return
		}
		switch state.State {
		case "maybe_nil":
			if !reportedMissingNil[root] {
				diags = append(diags, missingNilCheckAt(fn, root, primary))
				reportedMissingNil[root] = true
			}
		case "consumed", "maybe_consumed":
			key := fmt.Sprintf("HZN2103:%s:%d:%d", root, primary.Start.Line, primary.Start.Column)
			if !reportedAt[key] {
				reportedAt[key] = true
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2103",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("write to ringbuf reservation %q after submit or discard", root),
					Primary:  primary,
				})
			}
		}
	}
	var walk func([]ir.Statement)
	walk = func(stmts []ir.Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var":
				trackReserveStatement(stmt, ringMaps, states)
				// v0.3 alder Phase 2 (roadmap #18): if the RHS is a user-
				// helper call returning a resource, consult the helper's
				// ReturnEffect verdict and bind the result accordingly.
				// ReturnsResource → live (never-nil); ReturnsResourceMaybe →
				// maybe_nil (nil-check required); ReturnsAlias / Unknown /
				// None → do not track (downstream behavior matches Phase 1
				// "unknown" — no spurious diagnostics on the bound value).
				trackHelperReturnStatement(stmt, ringMaps, states, effects)
				// Register alias if the RHS is a plain ident of an already-tracked name.
				if src := aliasOf(stmt); src != "" {
					if _, ok := states[aliases.root(src)]; ok {
						aliases.register(stmt.Name, src)
					}
				}
			case "var_decl":
				checkExprHelperWrites(stmt.Value, checkWrite)
			case "assign":
				if varName, ok := selectorBase(stmt.Target); ok {
					checkWrite(varName, stmt.Span)
				}
				// #6 field-store aliasing: `container.slot = event` registers a
				// field edge so later selector reads (`container.slot`) resolve
				// back to event's root. Only fires when RHS is an ident of an
				// already-tracked name — integer/literal stores leave the graph
				// alone.
				if stmt.Target != nil && stmt.Target.Kind == "selector" &&
					stmt.Target.Operand != nil && stmt.Target.Operand.Kind == "ident" &&
					stmt.Value != nil && stmt.Value.Kind == "ident" {
					src := stmt.Value.Name
					if _, ok := states[aliases.root(src)]; ok {
						aliases.registerFieldStore(stmt.Target.Operand.Name, stmt.Target.Field, src)
					}
				}
			case "expr":
				if mapName, op, varName, ok := consumeCallResolved(stmt.Expr, aliases); ok {
					if _, ok := ringMaps[mapName]; !ok {
						break
					}
					root := aliases.root(varName)
					state, ok := states[root]
					if !ok {
						diags = append(diags, diag.Diagnostic{
							Code:     "HZN2101",
							Severity: diag.SeverityError,
							Message:  fmt.Sprintf("%s consumes unknown ringbuf reservation %q", op, varName),
							Primary:  stmt.Span,
						})
						break
					}
					switch state.State {
					case "maybe_nil":
						if !reportedMissingNil[root] {
							diags = append(diags, missingNilCheckAt(fn, root, stmt.Span))
							reportedMissingNil[root] = true
						}
						state.State = "consumed"
					case "consumed", "maybe_consumed":
						key := fmt.Sprintf("HZN2102:%s:%d:%d", root, stmt.Span.Start.Line, stmt.Span.Start.Column)
						if !reportedAt[key] {
							reportedAt[key] = true
							diags = append(diags, diag.Diagnostic{
								Code:     "HZN2102",
								Severity: diag.SeverityError,
								Message:  fmt.Sprintf("ringbuf reservation %q is submitted or discarded more than once", root),
								Primary:  stmt.Span,
							})
						}
					case "nil":
						key := fmt.Sprintf("HZN2105:%s:%d:%d", root, stmt.Span.Start.Line, stmt.Span.Start.Column)
						if !reportedAt[key] {
							reportedAt[key] = true
							diags = append(diags, diag.Diagnostic{
								Code:     "HZN2105",
								Severity: diag.SeverityError,
								Message:  fmt.Sprintf("nil ringbuf reservation %q cannot be submitted or discarded", root),
								Primary:  stmt.Span,
							})
						}
					case "escaped":
						// escaped: call already received the resource; treat as consumed.
						state.State = "consumed"
					default:
						state.State = "consumed"
					}
					states[root] = state
					break
				}
				if varName, ok := helperWriteBase(stmt.Expr); ok {
					checkWrite(varName, stmt.Span)
				}
				// Apply the user-helper effect summary to the call's args. For
				// known user helpers, transitions are precise (Consumes →
				// consumed, Preserves → unchanged, Mixed → maybe_consumed).
				// For Unknown / Escapes / non-user-helper call sites, the
				// fallback is Phase 1's "escaped" suppression.
				applyHelperEffectRingbuf(stmt.Expr, states, aliases, effects)
			case "if":
				outerStates := states
				scoped := stmt.Init != nil
				if scoped {
					states = cloneReserveStates(outerStates)
					walk([]ir.Statement{*stmt.Init})
				}
				func() {
					checkExprHelperWrites(stmt.Cond, checkWrite)
					if eqVars := nilCheckedVars(stmt.Cond); len(eqVars) > 0 {
						branchStates := cloneReserveStates(states)
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
							elseStates := cloneReserveStates(oldStates)
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
							states = mergeReserveBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
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
						branchStates := cloneReserveStates(states)
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
							elseStates := cloneReserveStates(oldStates)
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
							states = mergeReserveBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
							return
						}
						states = mergeReserveBranchStates(thenStates, oldStates, branchAlwaysReturns(stmt.Then), false)
						return
					}
					oldStates := states
					states = cloneReserveStates(oldStates)
					walk(stmt.Then)
					thenStates := states
					elseStates := oldStates
					if len(stmt.Else) > 0 {
						states = cloneReserveStates(oldStates)
						walk(stmt.Else)
						elseStates = states
					}
					states = mergeReserveBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
				}()
				if scoped {
					reportScopedLiveReservations(states, outerStates, reportLive, stmt.Span)
					states = pruneNewReserveStates(states, outerStates)
				}
			case "switch":
				walkReserveSwitch(stmt, &states, checkWrite, walk)
			case "for":
				// Bounded 2-iteration fixpoint for loop-carry state soundness (#5).
				// Walking the body once misses patterns like submit(event) inside a
				// loop where event was reserved outside — iteration 2 catches it.
				//
				// Walk init/post as flat statements so loop variables (e.g. i := 0)
				// are registered in states; they are not resource-carrying so no
				// ringbuf state changes, but skipping them is consistent with maps.go.
				if stmt.Init != nil {
					walk([]ir.Statement{*stmt.Init})
				}
				checkExprHelperWrites(stmt.Cond, checkWrite)
				if stmt.Post != nil {
					walk([]ir.Statement{*stmt.Post})
				}
				// Iteration 1: snapshot pre-loop state, walk body.
				savedStates := cloneReserveStates(states)
				walk(stmt.Body)
				afterIter1 := cloneReserveStates(states)
				// Merge pre-loop + post-iter-1 → may-have-iterated state.
				// This models the case where the body executed 0 or 1 times already.
				mayHaveIterated := mergeReserveBranchStates(savedStates, afterIter1, false, false)
				// Bounded 2-iteration walk. For the resource-state lattice values reachable
				// from v0.2 grammar (maybe_nil, live, consumed, maybe_consumed, nil, escaped),
				// two iterations suffice to detect cross-iteration regressions like
				// double-submit and write-after-submit. The lattice is finite and merge is
				// idempotent for these specific transitions in practice, but we do NOT
				// prove a general fixpoint theorem — if a future state value or transition
				// causes iter-3 to differ from iter-2, the fixpoint is unsound and should
				// be revisited (roadmap entry will track if it ever happens).
				// Range-over and for {} are not modeled here; HZN2200 rejects
				// unbounded for {} at AnalyzeLoops. (roadmap: v0.3+)
				states = mayHaveIterated
				walk(stmt.Body)
				afterIter2 := cloneReserveStates(states)
				// Post-loop state: merge iter-1 and iter-2 outcomes.
				states = mergeReserveBranchStates(afterIter1, afterIter2, false, false)
			case "return":
				for varName, state := range states {
					if state.State == "live" || state.State == "maybe_nil" || state.State == "maybe_consumed" {
						reportLive(varName, stmt.Span)
					}
				}
			}
		}
	}
	walk(functionStatements(fn))
	for varName, state := range states {
		if state.State == "consumed" || state.State == "nil" || state.State == "escaped" {
			continue
		}
		reportLive(varName, fn.Span)
	}
	return diags
}

// applyHelperEffectRingbuf transitions caller-side ringbuf reservation state
// at every call site, consulting the program-level HelperEffects summary.
//
// Three classes of call site:
//
//  1. Compiler-known ringbuf consume (Events.submit / Events.discard): NOT
//     handled here — consumeCall above intercepts these before the dispatcher
//     reaches applyHelperEffectRingbuf, and the consume-state transitions are
//     applied there. We early-return so the arg-ident is not double-processed
//     here.
//
//  2. User-helper call (bare-ident callee): per arg, consult
//     effects.EffectFor(name, i):
//     - Consumes → live | maybe_nil → consumed
//     - Preserves → state unchanged
//     - Mixed → live → maybe_consumed (lattice already supports this)
//     - Escapes / Unknown → fall back to Phase 1 behavior: live → escaped
//
//  3. Any other call (selector-form non-consume call like a future xdp helper
//     that doesn't exist today): fall back to Phase 1 escape, conservative.
//
// The function recurses into Args so nested calls (f(g(event))) are processed
// in lexical order — g's effect on event applies before f's. It also recurses
// into Operand/Left/Right/Func to catch calls inside binary expressions and
// the like.
//
// NOTE: ringbuf preserves the Phase 1 asymmetry vs maps/packet — the escaped
// fallback is gated on state == "live" so a `maybe_nil` reservation passed to
// an unanalyzable helper still fires HZN2100 on the next use. Maps/packet
// (Task 5/6) widen this gate; ringbuf does not.
func applyHelperEffectRingbuf(expr *ir.Expr, states map[string]reserveState, aliases *aliasGraph, effects HelperEffects) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		// Compiler-known consume calls are intercepted by consumeCallResolved
		// in the dispatcher above; do not double-process their arg here.
		// We deliberately pass a fresh empty aliasGraph so the gate only
		// fires for syntactically-recognized consume shapes (ident or
		// selector arg) — alias-resolution itself happened up there.
		if _, _, _, ok := consumeCallResolved(expr, aliases); !ok {
			helperName := userHelperName(expr.Func)
			// #7 (B3) path-sensitive specialization: when the call site
			// includes literal args, EffectForCall re-walks the helper body
			// under the substitution to produce a tighter per-call effect
			// vector. Computed once per call site; cached internally by
			// HelperEffects.bySite (bounded at 32 entries per helper).
			var perCallEffects []HelperEffect
			if helperName != "" {
				perCallEffects = effects.EffectForCall(helperName, expr.Args)
			}
			// v0.3 alder Phase 2 (roadmap #18): if the helper's return
			// verdict is ReturnsAlias, the helper exfiltrates one of its
			// arguments via return. The matching argument must be widened
			// to "escaped" so the caller's downstream usage is suppressed
			// (the helper may have leaked it onward). For Unknown, keep
			// Phase 1 escape behavior (already handled by the param switch
			// default below).
			returnVerdict := ReturnEffectNone
			if helperName != "" {
				returnVerdict = effects.ReturnEffectFor(helperName)
			}
			for i := range expr.Args {
				arg := &expr.Args[i]
				// Recurse into the arg FIRST so nested calls like
				// outer(inner(event)) classify inner's effect on event
				// before outer's. This matches lexical evaluation order.
				applyHelperEffectRingbuf(arg, states, aliases, effects)
				if arg.Kind != "ident" {
					continue
				}
				root := aliases.root(arg.Name)
				state, ok := states[root]
				if !ok {
					continue
				}
				if helperName != "" {
					effect := HelperEffectUnknown
					if i < len(perCallEffects) {
						effect = perCallEffects[i]
					}
					// ReturnsAlias dominates: the helper returned this
					// argument back out, so caller-side tracking must widen
					// to escaped even if the per-param effect said
					// Preserves. Without this, a passthrough helper would
					// leave the reservation "live" and HZN2104 would fire
					// at the entry's return — but the helper has potentially
					// exfiltrated the reservation, so silencing matches the
					// Phase 1 escape posture.
					if returnVerdict == ReturnEffectReturnsAlias {
						if state.State == "live" || state.State == "maybe_nil" {
							state.State = "escaped"
							states[root] = state
						}
						continue
					}
					switch effect {
					case HelperEffectConsumes:
						if state.State == "live" || state.State == "maybe_nil" {
							state.State = "consumed"
							states[root] = state
						}
					case HelperEffectPreserves:
						// State unchanged — helper provably does not consume.
					case HelperEffectMixed:
						if state.State == "live" {
							state.State = "maybe_consumed"
							states[root] = state
						}
					default:
						// HelperEffectEscapes or HelperEffectUnknown: fall
						// back to Phase 1 escape behavior.
						if state.State == "live" {
							state.State = "escaped"
							states[root] = state
						}
					}
					continue
				}
				// Non-user-helper call site (selector form that wasn't a
				// known consume): Phase 1 fallback.
				if state.State == "live" {
					state.State = "escaped"
					states[root] = state
				}
			}
		}
	}
	// Recurse into non-arg sub-expressions (func selector, operands, etc.).
	applyHelperEffectRingbuf(expr.Operand, states, aliases, effects)
	applyHelperEffectRingbuf(expr.Left, states, aliases, effects)
	applyHelperEffectRingbuf(expr.Right, states, aliases, effects)
	applyHelperEffectRingbuf(expr.Func, states, aliases, effects)
}

func missingNilCheck(fn ir.Function, varName string) diag.Diagnostic {
	return missingNilCheckAt(fn, varName, fn.Span)
}

func missingNilCheckAt(fn ir.Function, varName string, primary span.Span) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN2100",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("ringbuf reservation %q must be checked against nil before use", varName),
		Primary:  primary,
		Suggest:  fmt.Sprintf("guard %s with `if %s == nil { return 0 }` before writing or submitting it", varName, varName),
	}
}

func liveOnReturnAt(fn ir.Function, varName string, primary span.Span) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN2104",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("ringbuf reservation %q may return without submit or discard", varName),
		Primary:  primary,
	}
}

func functionStatements(fn ir.Function) []ir.Statement {
	var out []ir.Statement
	for _, block := range fn.Body {
		out = append(out, block.Statements...)
	}
	return out
}

// hasTypedStatements reports whether fn contains at least one typed IR statement
// (i.e. a statement whose Kind is not "raw", "unknown", or ""). Functions that
// return false have no typed-IR coverage and are skipped by Collect and the
// stack estimator; once all IR-build paths emit typed statements this guard
// becomes vacuously true everywhere and can be removed.
func hasTypedStatements(fn ir.Function) bool {
	for _, stmt := range functionStatements(fn) {
		switch stmt.Kind {
		case "raw", "unknown", "":
			continue
		default:
			return true
		}
	}
	return false
}

func cloneReserveStates(in map[string]reserveState) map[string]reserveState {
	out := make(map[string]reserveState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pruneNewReserveStates(in map[string]reserveState, outer map[string]reserveState) map[string]reserveState {
	out := cloneReserveStates(in)
	for name := range out {
		if _, ok := outer[name]; !ok {
			delete(out, name)
		}
	}
	return out
}

func reportScopedLiveReservations(states map[string]reserveState, outer map[string]reserveState, report func(string, span.Span), primary span.Span) {
	for name, state := range states {
		if _, ok := outer[name]; ok {
			continue
		}
		if state.State == "live" || state.State == "maybe_nil" || state.State == "maybe_consumed" {
			report(name, primary)
		}
		// "escaped" is not reported — the resource may have been consumed by
		// the callee; reporting would be a false positive.
	}
}

func trackReserveStatement(stmt ir.Statement, ringMaps map[string]ir.Map, states map[string]reserveState) {
	mapName, ok := reserveCall(stmt.Value)
	if !ok {
		return
	}
	if _, ok := ringMaps[mapName]; !ok {
		return
	}
	states[stmt.Name] = reserveState{Map: mapName, State: "maybe_nil"}
}

// trackHelperReturnStatement binds a short_var name to a reserveState entry
// when the RHS is a user-helper call whose ReturnEffect verdict says the
// helper returns a freshly-created resource (ReturnsResource: live;
// ReturnsResourceMaybe: maybe_nil). Other verdicts (ReturnsAlias, Unknown,
// None) leave states untouched — the bound value either is not a tracked
// reservation or has already-escaped semantics that match Phase 1's
// suppression. v0.3 alder Phase 2 (roadmap #18).
//
// The reserveState.Map field is left empty because the bound value's origin
// is the helper, not a specific ringbuf map — downstream consume-site logic
// only consumes by name, not by map. This is the same shape Phase 1
// tolerated for helper-returned values via the escape fallback.
func trackHelperReturnStatement(stmt ir.Statement, ringMaps map[string]ir.Map, states map[string]reserveState, effects HelperEffects) {
	if stmt.Value == nil || stmt.Value.Kind != "call" || stmt.Value.Func == nil {
		return
	}
	if stmt.Value.Func.Kind != "ident" {
		return
	}
	helperName := stmt.Value.Func.Name
	switch effects.ReturnEffectFor(helperName) {
	case ReturnEffectReturnsResource:
		// Definitely-live freshly-created resource. Bind as "live" so callers
		// may submit without a nil-check.
		states[stmt.Name] = reserveState{State: "live"}
	case ReturnEffectReturnsResourceMaybe:
		// Sometimes-nil. Bind as "maybe_nil" — caller must nil-check before
		// use, matching a direct reserve() site.
		states[stmt.Name] = reserveState{State: "maybe_nil"}
	case ReturnEffectUnknown, ReturnEffectReturnsAlias:
		// Un-analyzable / aliased return. Bind as "escaped" so downstream
		// consume calls (Events.submit(e)) silently transition without
		// firing HZN2101 "unknown reservation" — matching Phase 1's escape
		// suppression for unsummarizable helper bodies.
		states[stmt.Name] = reserveState{State: "escaped"}
	default:
		// ReturnEffectNone: helper does not return a tracked resource. Do
		// not register.
	}
}

func walkReserveSwitch(stmt ir.Statement, states *map[string]reserveState, checkWrite func(string, span.Span), walk func([]ir.Statement)) {
	checkExprHelperWrites(stmt.Value, checkWrite)
	oldStates := *states
	mergedStates := map[string]reserveState{}
	mergedReturns := false
	haveBranch := false
	hasDefault := false
	mergeBranch := func(branchStates map[string]reserveState, returns bool) {
		if !haveBranch {
			mergedStates = cloneReserveStates(branchStates)
			mergedReturns = returns
			haveBranch = true
			return
		}
		mergedStates = mergeReserveBranchStates(mergedStates, branchStates, mergedReturns, returns)
		mergedReturns = mergedReturns && returns
	}
	for _, c := range stmt.Cases {
		for i := range c.Values {
			checkExprHelperWrites(&c.Values[i], checkWrite)
		}
		if c.Default {
			hasDefault = true
		}
		*states = cloneReserveStates(oldStates)
		walk(c.Body)
		mergeBranch(*states, branchAlwaysReturns(c.Body))
	}
	if !hasDefault {
		mergeBranch(oldStates, false)
	}
	*states = mergedStates
}

func mergeReserveBranchStates(thenStates map[string]reserveState, elseStates map[string]reserveState, thenReturns bool, elseReturns bool) map[string]reserveState {
	switch {
	case thenReturns && elseReturns:
		return map[string]reserveState{}
	case thenReturns:
		return cloneReserveStates(elseStates)
	case elseReturns:
		return cloneReserveStates(thenStates)
	}

	out := cloneReserveStates(thenStates)
	for name, elseState := range elseStates {
		thenState, ok := out[name]
		if !ok {
			out[name] = elseState
			continue
		}
		out[name] = mergeReserveState(thenState, elseState)
	}
	return out
}

func mergeReserveState(a reserveState, b reserveState) reserveState {
	if a.Map == "" {
		return b
	}
	if b.Map == "" {
		return a
	}
	state := reserveState{Map: a.Map, State: mergeReserveStateName(a.State, b.State)}
	if state.Map == "" {
		state.Map = b.Map
	}
	return state
}

func mergeReserveStateName(a string, b string) string {
	if a == b {
		return a
	}
	// "escaped" merges with anything → "escaped": we can never know whether
	// the callee consumed the resource, so we conservatively suppress
	// HZN2104. Escaped overrides even "live" to prevent false positives.
	if a == "escaped" || b == "escaped" {
		return "escaped"
	}
	if a == "maybe_nil" || b == "maybe_nil" {
		return "maybe_nil"
	}
	if a == "maybe_consumed" || b == "maybe_consumed" {
		return "maybe_consumed"
	}
	if a == "live" && b == "nil" || a == "nil" && b == "live" {
		return "maybe_nil"
	}
	if a == "live" || b == "live" {
		return "maybe_consumed"
	}
	if a == "nil" || b == "nil" {
		return "consumed"
	}
	return "maybe_consumed"
}

func reserveCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" {
		return "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || method != "reserve" {
		return "", false
	}
	if operand.Kind != "ident" {
		return "", false
	}
	return operand.Name, true
}

func consumeCall(expr *ir.Expr) (string, string, string, bool) {
	if expr == nil || expr.Kind != "call" || len(expr.Args) != 1 {
		return "", "", "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || method != "submit" && method != "discard" || operand.Kind != "ident" {
		return "", "", "", false
	}
	arg := expr.Args[0]
	if arg.Kind != "ident" {
		return "", "", "", false
	}
	return operand.Name, method, arg.Name, true
}

// consumeCallResolved is consumeCall extended to recognize selector-form args
// (`Events.submit(container.slot)`) by resolving them through the alias graph's
// field-store edges (#6). For ident args, it matches consumeCall verbatim. For
// selector args, it returns the registered field-store source when one exists;
// otherwise returns ok=false so callers fall through to their non-consume
// dispatch.
func consumeCallResolved(expr *ir.Expr, aliases *aliasGraph) (string, string, string, bool) {
	if expr == nil || expr.Kind != "call" || len(expr.Args) != 1 {
		return "", "", "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || method != "submit" && method != "discard" || operand.Kind != "ident" {
		return "", "", "", false
	}
	arg := &expr.Args[0]
	switch arg.Kind {
	case "ident":
		return operand.Name, method, arg.Name, true
	case "selector":
		if rootName := aliases.rootOfSelector(arg); rootName != "" {
			return operand.Name, method, rootName, true
		}
	}
	return "", "", "", false
}

func helperWriteBase(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" || len(expr.Args) == 0 {
		return "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || operand.Kind != "ident" || operand.Name != "bpf" {
		return "", false
	}
	switch method {
	case "current_comm", "probe_read_user_str":
		return addressSelectorBase(&expr.Args[0])
	default:
		return "", false
	}
}

func checkExprHelperWrites(expr *ir.Expr, checkWrite func(string, span.Span)) {
	if expr == nil {
		return
	}
	if varName, ok := helperWriteBase(expr); ok {
		checkWrite(varName, expr.Span)
	}
	checkExprHelperWrites(expr.Operand, checkWrite)
	checkExprHelperWrites(expr.Left, checkWrite)
	checkExprHelperWrites(expr.Right, checkWrite)
	checkExprHelperWrites(expr.Func, checkWrite)
	for i := range expr.Args {
		checkExprHelperWrites(&expr.Args[i], checkWrite)
	}
	for i := range expr.Fields {
		checkExprHelperWrites(&expr.Fields[i].Value, checkWrite)
	}
}

func addressSelectorBase(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "unary" || expr.Op != "&" || expr.Operand == nil {
		return "", false
	}
	return selectorBase(expr.Operand)
}

func selectorMethod(expr *ir.Expr) (ir.Expr, string, bool) {
	if expr == nil || expr.Kind != "selector" || expr.Operand == nil {
		return ir.Expr{}, "", false
	}
	return *expr.Operand, expr.Field, true
}

func selectorBase(expr *ir.Expr) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Kind {
	case "ident":
		return expr.Name, true
	case "selector":
		return selectorBase(expr.Operand)
	default:
		return "", false
	}
}


func branchAlwaysReturns(stmts []ir.Statement) bool {
	if len(stmts) == 0 {
		return false
	}
	last := stmts[len(stmts)-1]
	if last.Kind == "return" {
		return true
	}
	if last.Kind == "if" && branchAlwaysReturns(last.Then) && branchAlwaysReturns(last.Else) {
		return true
	}
	if last.Kind == "switch" {
		hasDefault := false
		for _, c := range last.Cases {
			if c.Default {
				hasDefault = true
			}
			if !branchAlwaysReturns(c.Body) {
				return false
			}
		}
		return hasDefault && len(last.Cases) > 0
	}
	return false
}
