package validate

import (
	"fmt"
	"strconv"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

// AnalyzeMaps runs the maps validator's rule logic over pre-collected sites.
// Schema validation (map config, max_entries) does not touch the IR and runs
// unconditionally. Lookup nil-check analysis (the branch-aware state machine in
// validateTypedMapLookups) re-walks per-function but uses sites.MapLookup as the
// index to avoid iterating all program functions — only functions with at least
// one map lookup site are analyzed.
//
// effects is the program-level user-helper effect summary built once by
// validate.Program (Phase 2 #13). When a tracked lookup result is passed to a
// user helper, applyHelperEffectLookup consults this summary to decide whether
// to widen the caller's state to `escaped`. For maps the load-bearing case is
// Preserves: a helper that does not consume the lookup pointer should NOT
// suppress the caller's deref check. Consumes/Mixed at the caller side are
// indistinguishable from Preserves for the lookup state machine — the caller
// still has to nil-check before its own deref because lookup pointers are
// not "owned" the way ringbuf reservations are.
func AnalyzeMaps(program ir.Program, sites Sites, effects HelperEffects) []diag.Diagnostic {
	var diags []diag.Diagnostic
	for _, m := range program.Maps {
		switch m.Kind {
		case ir.MapKindRingbuf:
			if m.Val.Name == "" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2400",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("ringbuf map %q is missing a value type", m.Name),
				})
			}
		case ir.MapKindHash, ir.MapKindArray, ir.MapKindPerCPUHash, ir.MapKindPerCPUArray, ir.MapKindLRUHash, ir.MapKindLRUPerCPU:
			if m.Key.Name == "" || m.Val.Name == "" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN2401",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s map %q requires key and value types", m.Kind, m.Name),
				})
			}
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2402",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("unsupported map kind %q", m.Kind),
			})
		}
		diags = append(diags, validateMapMaxEntries(m)...)
	}

	// Build the lookup-map registry for the state machine.
	lookupMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind.IsLookup() {
			lookupMaps[m.Name] = m
		}
	}
	if len(lookupMaps) > 0 {
		// Use sites.MapLookup as the index: only functions that hold at least one
		// map-lookup site need nil-check analysis.
		seen := map[*ir.Function]bool{}
		for _, site := range sites.MapLookup {
			if seen[site.Function] {
				continue
			}
			seen[site.Function] = true
			diags = append(diags, validateTypedMapLookups(*site.Function, lookupMaps, effects)...)
		}
	}
	return diags
}

func validateMapMaxEntries(m ir.Map) []diag.Diagnostic {
	if m.MaxEntries == "" {
		return nil
	}
	value, err := strconv.ParseUint(m.MaxEntries, 0, 32)
	if err != nil || value == 0 {
		return []diag.Diagnostic{{
			Code:     "HZN2403",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("map %q max_entries must be a positive integer literal", m.Name),
			Primary:  m.Span,
		}}
	}
	if m.Kind == ir.MapKindRingbuf && value&(value-1) != 0 {
		return []diag.Diagnostic{{
			Code:     "HZN2404",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("ringbuf map %q max_entries must be a power of two", m.Name),
			Primary:  m.Span,
		}}
	}
	return nil
}

type lookupState struct {
	Source string
	Label  string
	State  string
}

func validateTypedMapLookups(fn ir.Function, lookupMaps map[string]ir.Map, effects HelperEffects) []diag.Diagnostic {
	states := map[string]lookupState{}
	aliases := newAliasGraph()
	reported := map[string]bool{}
	var diags []diag.Diagnostic
	reportDeref := func(varName string, state lookupState, primary span.Span) {
		key := fmt.Sprintf("%s:%d:%d", varName, primary.Start.Line, primary.Start.Column)
		if reported[key] {
			return
		}
		reported[key] = true
		switch state.State {
		case "nil":
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2501",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("nil %s %q cannot be dereferenced", state.Label, varName),
				Primary:  primary,
			})
		case "escaped":
			// escaped: resource passed to unknown function; skip deref warning
			// since we cannot determine its nil-status post-call.
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2500",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("%s %q must be checked against nil before dereference", state.Label, varName),
				Primary:  primary,
				Suggest:  fmt.Sprintf("guard %s with `%s` before reading or writing it", varName, nilGuardSuggestion(fn, varName)),
			})
		}
	}
	var checkExpr func(*ir.Expr)
	checkExpr = func(expr *ir.Expr) {
		if expr == nil {
			return
		}
		if expr.Kind == "selector" {
			if varName, ok := selectorBase(expr); ok {
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
					if mapName, ok := mapLookupCall(stmt.Value); ok {
						if _, ok := lookupMaps[mapName]; ok {
							states[stmt.Name] = lookupState{Source: mapName, Label: "map lookup result", State: "maybe_nil"}
						}
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
			case "expr":
				checkExpr(stmt.Expr)
				// Apply the user-helper effect summary to the call's args.
				// For maps, Preserves is the load-bearing case — it stops
				// the Phase 1 over-suppression that turned `maybe_nil` →
				// `escaped` on any call, silencing the caller's downstream
				// deref check. Consumes / Mixed at the caller side do not
				// change state for lookups (the caller still needs its own
				// nil-check before its own deref). Escapes / Unknown fall
				// back to Phase 1 behavior.
				applyHelperEffectLookup(stmt.Expr, states, aliases, effects)
			case "return":
				checkExpr(stmt.Value)
			case "if":
				outerStates := states
				scoped := stmt.Init != nil
				if scoped {
					states = cloneLookupStates(outerStates)
					walk([]ir.Statement{*stmt.Init})
				}
				func() {
					checkExpr(stmt.Cond)
					if eqVars := nilCheckedVars(stmt.Cond); len(eqVars) > 0 {
						branchStates := cloneLookupStates(states)
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
							elseStates := cloneLookupStates(oldStates)
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
							states = mergeLookupBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
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
						branchStates := cloneLookupStates(states)
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
							elseStates := cloneLookupStates(oldStates)
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
							states = mergeLookupBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
							return
						}
						return
					}
					oldStates := states
					states = cloneLookupStates(oldStates)
					walk(stmt.Then)
					thenStates := states
					elseStates := oldStates
					if len(stmt.Else) > 0 {
						states = cloneLookupStates(oldStates)
						walk(stmt.Else)
						elseStates = states
					}
					states = mergeLookupBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
				}()
				if scoped {
					states = pruneNewLookupStates(states, outerStates)
				}
			case "switch":
				checkExpr(stmt.Value)
				oldStates := states
				mergedStates := map[string]lookupState{}
				mergedReturns := false
				haveBranch := false
				hasDefault := false
				mergeBranch := func(branchStates map[string]lookupState, returns bool) {
					if !haveBranch {
						mergedStates = cloneLookupStates(branchStates)
						mergedReturns = returns
						haveBranch = true
						return
					}
					mergedStates = mergeLookupBranchStates(mergedStates, branchStates, mergedReturns, returns)
					mergedReturns = mergedReturns && returns
				}
				for _, c := range stmt.Cases {
					for i := range c.Values {
						checkExpr(&c.Values[i])
					}
					if c.Default {
						hasDefault = true
					}
					states = cloneLookupStates(oldStates)
					walk(c.Body)
					mergeBranch(states, branchAlwaysReturns(c.Body))
				}
				if !hasDefault {
					mergeBranch(oldStates, false)
				}
				states = mergedStates
			case "for":
				// Bounded 2-iteration walk for loop-carry state soundness (#5).
				// The lookup-state lattice (nil → maybe_nil → guarded) has height 2
				// and a provably monotone join (lub), so two iterations are sufficient
				// — iter-3 is always identical to iter-2 for any reachable transition.
				// Walking the body once misses unguarded derefs on iteration 2+ when a
				// lookup state is already maybe_nil.
				// Range-over and for {} not modeled; HZN2200 rejects for {}.
				if stmt.Init != nil {
					walk([]ir.Statement{*stmt.Init})
				}
				checkExpr(stmt.Cond)
				if stmt.Post != nil {
					walk([]ir.Statement{*stmt.Post})
				}
				// Iteration 1: snapshot pre-loop state, walk body.
				savedStates := cloneLookupStates(states)
				walk(stmt.Body)
				afterIter1 := cloneLookupStates(states)
				// Merge pre-loop + post-iter-1 → may-have-iterated state.
				mayHaveIterated := mergeLookupBranchStates(savedStates, afterIter1, false, false)
				// Iteration 2: walk body again; diagnostics here catch cross-iteration issues.
				states = mayHaveIterated
				walk(stmt.Body)
				afterIter2 := cloneLookupStates(states)
				// Post-loop state: merge iter-1 and iter-2 outcomes.
				states = mergeLookupBranchStates(afterIter1, afterIter2, false, false)
			}
		}
	}
	walk(functionStatements(fn))
	return diags
}

// applyHelperEffectLookup transitions caller-side map-lookup state at every
// call site, consulting the program-level HelperEffects summary.
//
// For maps, the Phase 1 rule was: any non-live lookup state passed to ANY
// call widens to "escaped" — including `maybe_nil`, which over-suppressed
// the caller's downstream deref check (HZN2500). This is the load-bearing
// regression Task 5 fixes.
//
// Per-call-site behavior:
//
//  1. User-helper call (bare-ident callee): per arg, consult
//     effects.EffectFor(name, i):
//     - Preserves → state unchanged (the load-bearing case — stops over-
//       suppression so the caller's deref check still fires).
//     - Consumes  → state unchanged. Lookup pointers are not "owned" the
//       way ringbuf reservations are; the helper's internal deref does not
//       absolve the caller of its own nil-check. Indistinguishable from
//       Preserves at the caller side today; the distinction is kept on
//       the summary side because v0.3 may use it differently.
//     - Mixed     → state unchanged. Same reasoning as Consumes.
//     - Escapes / Unknown → Phase 1 fallback: any non-live state widens
//       to "escaped".
//
//  2. Any other call (compiler-known map method like Counts.lookup, or a
//     selector form that isn't a known helper): fall back to Phase 1
//     escape — any non-live state widens to "escaped". This preserves the
//     conservative behavior for call sites we cannot precisely classify.
//
// The function recurses into Args so nested calls (f(g(count))) are
// processed in lexical order — g's effect on count applies before f's.
//
// NOTE: maps preserves the Phase 1 asymmetry vs ringbuf — escape applies to
// ANY non-live state (including `maybe_nil`), not just `live`. The fallback
// gate is `state.State != "live" && state.State != "escaped"`, matching
// pre-Task-5 behavior for unanalyzable calls.
func applyHelperEffectLookup(expr *ir.Expr, states map[string]lookupState, aliases *aliasGraph, effects HelperEffects) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		helperName := userHelperName(expr.Func)
		for i := range expr.Args {
			arg := &expr.Args[i]
			// Recurse into the arg FIRST so nested calls classify their
			// effect on the arg before the outer call.
			applyHelperEffectLookup(arg, states, aliases, effects)
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
					// State unchanged — for maps, the caller still owes a
					// nil-check before its own deref regardless of what
					// the helper did internally.
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
	applyHelperEffectLookup(expr.Operand, states, aliases, effects)
	applyHelperEffectLookup(expr.Left, states, aliases, effects)
	applyHelperEffectLookup(expr.Right, states, aliases, effects)
	applyHelperEffectLookup(expr.Func, states, aliases, effects)
}

func nilGuardSuggestion(fn ir.Function, varName string) string {
	if fn.Section.Kind == ir.ProgramXDP {
		return fmt.Sprintf("if %s == nil { return xdp.Pass }", varName)
	}
	if fn.Section.Kind == ir.ProgramTC {
		return fmt.Sprintf("if %s == nil { return tc.OK }", varName)
	}
	if fn.Section.Kind == ir.ProgramCgroup {
		return fmt.Sprintf("if %s == nil { return cgroup.Allow }", varName)
	}
	if fn.Section.Kind == ir.ProgramLSM {
		return fmt.Sprintf("if %s == nil { return lsm.Allow }", varName)
	}
	return fmt.Sprintf("if %s == nil { return 0 }", varName)
}

func mapLookupCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" {
		return "", false
	}
	operand, method, ok := selectorMethod(expr.Func)
	if !ok || method != "lookup" || operand.Kind != "ident" {
		return "", false
	}
	return operand.Name, true
}


func cloneLookupStates(in map[string]lookupState) map[string]lookupState {
	out := make(map[string]lookupState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pruneNewLookupStates(in map[string]lookupState, outer map[string]lookupState) map[string]lookupState {
	out := cloneLookupStates(in)
	for name := range out {
		if _, ok := outer[name]; !ok {
			delete(out, name)
		}
	}
	return out
}

func mergeLookupBranchStates(thenStates map[string]lookupState, elseStates map[string]lookupState, thenReturns bool, elseReturns bool) map[string]lookupState {
	switch {
	case thenReturns && elseReturns:
		return map[string]lookupState{}
	case thenReturns:
		return cloneLookupStates(elseStates)
	case elseReturns:
		return cloneLookupStates(thenStates)
	}

	out := cloneLookupStates(thenStates)
	for name, elseState := range elseStates {
		thenState, ok := out[name]
		if !ok {
			out[name] = elseState
			continue
		}
		out[name] = mergeLookupState(thenState, elseState)
	}
	return out
}

func mergeLookupState(a lookupState, b lookupState) lookupState {
	if a.Source == "" {
		return b
	}
	if b.Source == "" {
		return a
	}
	return lookupState{
		Source: a.Source,
		Label:  a.Label,
		State:  mergeNilPromotionState(a.State, b.State),
	}
}

func mergeNilPromotionState(a string, b string) string {
	// "escaped" merges with anything → "escaped": we can never know whether
	// the callee consumed the resource, so we conservatively suppress HZN2500/HZN2600.
	// Escaped overrides even "live" to prevent false positives.
	if a == "escaped" || b == "escaped" {
		return "escaped"
	}
	if a == b {
		return a
	}
	return "maybe_nil"
}
