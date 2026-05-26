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
func AnalyzePacket(program ir.Program, sites Sites) []diag.Diagnostic {
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
		diags = append(diags, validateXDPPacketHeaders(*site.Function)...)
	}
	return diags
}

type packetHeaderState struct {
	Helper string
	State  string
}

func validateXDPPacketHeaders(fn ir.Function) []diag.Diagnostic {
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
			case "expr":
				checkExpr(stmt.Expr)
				// Detect call-argument escapes for packet header states.
				checkArgEscapesPacket(stmt.Expr, states, aliases)
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
					if varName, ok := nilComparedVar(stmt.Cond, "=="); ok {
						root := aliases.root(varName)
						branchStates := clonePacketHeaderStates(states)
						if state, ok := branchStates[root]; ok && state.State == "maybe_nil" {
							state.State = "nil"
							branchStates[root] = state
						}
						oldStates := states
						states = branchStates
						walk(stmt.Then)
						thenStates := states
						states = oldStates
						if len(stmt.Else) > 0 {
							elseStates := clonePacketHeaderStates(oldStates)
							if state, ok := elseStates[root]; ok && state.State == "maybe_nil" {
								state.State = "live"
								elseStates[root] = state
							}
							states = elseStates
							walk(stmt.Else)
							elseStates = states
							states = mergePacketBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
							return
						}
						if branchAlwaysReturns(stmt.Then) {
							if state, ok := states[root]; ok && state.State == "maybe_nil" {
								state.State = "live"
								states[root] = state
							}
						}
						return
					}
					if varName, ok := nilComparedVar(stmt.Cond, "!="); ok {
						root := aliases.root(varName)
						branchStates := clonePacketHeaderStates(states)
						if state, ok := branchStates[root]; ok && state.State == "maybe_nil" {
							state.State = "live"
							branchStates[root] = state
						}
						oldStates := states
						states = branchStates
						walk(stmt.Then)
						thenStates := states
						states = oldStates
						if len(stmt.Else) > 0 {
							elseStates := clonePacketHeaderStates(oldStates)
							if state, ok := elseStates[root]; ok && state.State == "maybe_nil" {
								state.State = "nil"
								elseStates[root] = state
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
				if stmt.Init != nil {
					walk([]ir.Statement{*stmt.Init})
				}
				checkExpr(stmt.Cond)
				if stmt.Post != nil {
					walk([]ir.Statement{*stmt.Post})
				}
				walk(stmt.Body)
			}
		}
	}
	walk(functionStatements(fn))
	return diags
}

// checkArgEscapesPacket marks packet header states as "escaped" when passed as
// call arguments. Escaped headers suppress HZN2600 deref checks post-call.
// Cross-function tracking deferred to Phase 2 #13.
//
// See validate/ringbuf.go::checkArgEscapesRingbuf for the rationale on the
// "any non-live state escapes" rule (asymmetric vs ringbuf's "only live escapes").
func checkArgEscapesPacket(expr *ir.Expr, states map[string]packetHeaderState, aliases *aliasGraph) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		for i := range expr.Args {
			arg := &expr.Args[i]
			if arg.Kind == "ident" {
				root := aliases.root(arg.Name)
				if state, ok := states[root]; ok && state.State != "live" && state.State != "escaped" {
					state.State = "escaped"
					states[root] = state
				}
			}
			checkArgEscapesPacket(arg, states, aliases)
		}
	}
	checkArgEscapesPacket(expr.Operand, states, aliases)
	checkArgEscapesPacket(expr.Left, states, aliases)
	checkArgEscapesPacket(expr.Right, states, aliases)
	checkArgEscapesPacket(expr.Func, states, aliases)
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
