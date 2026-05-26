package validate

import (
	"fmt"
	"regexp"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

var (
	ringReserveRE  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*([A-Za-z_][A-Za-z0-9_]*)\.reserve\(\)\s*$`)
	ringNilCheckRE = regexp.MustCompile(`\bif\s+(?:([A-Za-z_][A-Za-z0-9_]*)\s*==\s*nil|nil\s*==\s*([A-Za-z_][A-Za-z0-9_]*))\b`)
	ringConsumeRE  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.(submit|discard)\(([A-Za-z_][A-Za-z0-9_]*)\)\s*$`)
	ringWriteRE    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.[A-Za-z_][A-Za-z0-9_]*\s*=`)
)

// AnalyzeRingbuf runs the ringbuf validator's rule logic over pre-collected sites.
// The state-machine analysis (maybe_nil → live → consumed) requires branch-
// merging control-flow context that Sites does not expose. sites.RingbufReserve
// is the load-bearing index of functions that hold reserve sites; the state
// machine re-walk (validateTypedRingbuf) is run only for those functions. Typed
// functions that contain no ringbuf reserves are skipped entirely — they cannot
// produce ringbuf diagnostics. Legacy text-path functions (hasTypedStatements
// == false) are still walked via bodyLines regardless of the Sites index, because
// Collect skips non-typed functions; they remain reachable until the regex
// fallback is removed in roadmap Task 3 (v0.3).
func AnalyzeRingbuf(program ir.Program, sites Sites) []diag.Diagnostic {
	ringMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf {
			ringMaps[m.Name] = m
		}
	}
	if len(ringMaps) == 0 {
		return nil
	}

	// Build the set of functions that contain at least one ringbuf reserve site.
	// This is the index that drives the typed-path analysis.
	interesting := make(map[*ir.Function]struct{}, len(sites.RingbufReserve))
	for _, s := range sites.RingbufReserve {
		interesting[s.Function] = struct{}{}
	}

	var diags []diag.Diagnostic
	for i := range program.Functions {
		fn := &program.Functions[i]
		if hasTypedStatements(*fn) {
			if _, ok := interesting[fn]; !ok {
				// Typed function with no ringbuf reserves: cannot produce any
				// ringbuf diagnostic. Skip to avoid unnecessary re-walks.
				continue
			}
			diags = append(diags, validateTypedRingbuf(*fn, ringMaps)...)
			continue
		}
		states := map[string]reserveState{}
		reportedMissingNil := map[string]bool{}
		for _, line := range bodyLines(*fn) {
			if match := ringReserveRE.FindStringSubmatch(line); len(match) == 3 {
				varName, mapName := match[1], match[2]
				if _, ok := ringMaps[mapName]; ok {
					states[varName] = reserveState{Map: mapName, State: "maybe_nil"}
				}
				continue
			}
			if match := ringNilCheckRE.FindStringSubmatch(line); len(match) == 3 {
				varName := match[1]
				if varName == "" {
					varName = match[2]
				}
				if state, ok := states[varName]; ok && state.State == "maybe_nil" {
					state.State = "live"
					states[varName] = state
				}
				continue
			}
			if match := ringConsumeRE.FindStringSubmatch(line); len(match) == 4 {
				mapName, op, varName := match[1], match[2], match[3]
				if _, ok := ringMaps[mapName]; !ok {
					continue
				}
				state, ok := states[varName]
				if !ok {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2101",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("%s consumes unknown ringbuf reservation %q", op, varName),
						Primary:  fn.Span,
					})
					continue
				}
				switch state.State {
				case "maybe_nil":
					if !reportedMissingNil[varName] {
						diags = append(diags, missingNilCheck(*fn, varName))
						reportedMissingNil[varName] = true
					}
					state.State = "consumed"
				case "consumed":
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2102",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("ringbuf reservation %q is submitted or discarded more than once", varName),
						Primary:  fn.Span,
					})
				default:
					state.State = "consumed"
				}
				states[varName] = state
				continue
			}
			if match := ringWriteRE.FindStringSubmatch(line); len(match) == 2 {
				varName := match[1]
				state, ok := states[varName]
				if !ok {
					continue
				}
				switch state.State {
				case "maybe_nil":
					if !reportedMissingNil[varName] {
						diags = append(diags, missingNilCheck(*fn, varName))
						reportedMissingNil[varName] = true
					}
				case "consumed":
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2103",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("write to ringbuf reservation %q after submit or discard", varName),
						Primary:  fn.Span,
					})
				}
			}
		}
		for varName, state := range states {
			if state.State == "consumed" {
				continue
			}
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2104",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("ringbuf reservation %q may return without submit or discard", varName),
				Primary:  fn.Span,
			})
		}
	}
	return diags
}

type reserveState struct {
	Map   string
	State string
}

func validateTypedRingbuf(fn ir.Function, ringMaps map[string]ir.Map) []diag.Diagnostic {
	states := map[string]reserveState{}
	aliases := newAliasGraph()
	reportedMissingNil := map[string]bool{}
	reportedLive := map[string]bool{}
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
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2103",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("write to ringbuf reservation %q after submit or discard", root),
				Primary:  primary,
			})
		}
	}
	var walk func([]ir.Statement)
	walk = func(stmts []ir.Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var":
				trackReserveStatement(stmt, ringMaps, states)
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
			case "expr":
				if mapName, op, varName, ok := consumeCall(stmt.Expr); ok {
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
						diags = append(diags, diag.Diagnostic{
							Code:     "HZN2102",
							Severity: diag.SeverityError,
							Message:  fmt.Sprintf("ringbuf reservation %q is submitted or discarded more than once", root),
							Primary:  stmt.Span,
						})
					case "nil":
						diags = append(diags, diag.Diagnostic{
							Code:     "HZN2105",
							Severity: diag.SeverityError,
							Message:  fmt.Sprintf("nil ringbuf reservation %q cannot be submitted or discarded", root),
							Primary:  stmt.Span,
						})
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
				// Detect call-argument escapes: if the expression is a call and any
				// argument is a tracked resource, mark that resource as "escaped".
				// Escaped resources do not trigger HZN2104 on return — we cannot
				// prove whether the callee consumed the reservation.
				checkArgEscapesRingbuf(stmt.Expr, states, aliases)
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
				// Iteration 2: walk body again with may-have-iterated state.
				// Any diagnostics (HZN2102, HZN2103, etc.) fired here catch
				// cross-iteration regressions — the state machine shows that a
				// second iteration would violate resource constraints.
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

// checkArgEscapesRingbuf marks ringbuf reservations as "escaped" when they
// are passed as arguments to a call expression. An escaped reservation is one
// whose consumption by the callee cannot be determined from intra-function
// analysis alone; marking it "escaped" suppresses the false-positive HZN2104
// (live-on-return). Cross-function (interprocedural) tracking is deferred to
// Phase 2 #13 (maple).
//
// Only direct ident arguments are inspected. Nested calls like f(g(x)) are
// also handled because checkArgEscapesRingbuf recurses into Args.
//
// NOTE: ringbuf requires state.State == "live" to escape, so a `maybe_nil`
// reservation passed to `helper(event)` still fires HZN2104 on return.
// This is deliberate — ringbuf wants the missing-nil-check diagnostic to
// stay loud even when the resource is also passed elsewhere. Maps/packet
// (in validate/maps.go and validate/packet.go) make the opposite trade,
// escaping any non-live state to silence dereference warnings; the rationale
// is that map lookups and packet headers commonly flow through helpers
// without strict nil-check ordering, where ringbuf submission is always
// a deliberate consume operation. Phase 2 #13 should preserve this
// asymmetry unless cross-function analysis exposes a sharper rule.
func checkArgEscapesRingbuf(expr *ir.Expr, states map[string]reserveState, aliases *aliasGraph) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		// Skip known ringbuf consume calls (submit/discard) — they are
		// handled by consumeCall and should not be double-processed here.
		if _, _, _, ok := consumeCall(expr); !ok {
			for i := range expr.Args {
				arg := &expr.Args[i]
				if arg.Kind == "ident" {
					root := aliases.root(arg.Name)
					if state, ok := states[root]; ok && state.State == "live" {
						state.State = "escaped"
						states[root] = state
					}
				}
				// Recurse into nested calls within this argument.
				checkArgEscapesRingbuf(arg, states, aliases)
			}
		}
	}
	// Recurse into non-arg sub-expressions (func selector, operands, etc.).
	checkArgEscapesRingbuf(expr.Operand, states, aliases)
	checkArgEscapesRingbuf(expr.Left, states, aliases)
	checkArgEscapesRingbuf(expr.Right, states, aliases)
	checkArgEscapesRingbuf(expr.Func, states, aliases)
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

func bodyLines(fn ir.Function) []string {
	text := fn.BodyText
	if text == "" {
		for _, block := range fn.Body {
			for _, stmt := range block.Statements {
				if stmt.Value != nil && stmt.Value.Kind == "raw" {
					text += "\n" + stmt.Value.Value
				}
			}
		}
	}
	text = strings.ReplaceAll(text, "{", "{\n")
	text = strings.ReplaceAll(text, "}", "\n}")
	raw := strings.Split(text, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || line == "{" || line == "}" {
			continue
		}
		lines = append(lines, strings.TrimSuffix(line, ";"))
	}
	return lines
}

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

func functionStatements(fn ir.Function) []ir.Statement {
	var out []ir.Statement
	for _, block := range fn.Body {
		out = append(out, block.Statements...)
	}
	return out
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
