package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

type packetHeaderState struct {
	Helper string
	State  string
}

func ValidatePacket(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if fn.Section.Kind != ir.ProgramXDP || !hasTypedStatements(fn) {
			continue
		}
		diags = append(diags, validateXDPPacketHeaders(fn)...)
	}
	return diags
}

func validateXDPPacketHeaders(fn ir.Function) []diag.Diagnostic {
	states := map[string]packetHeaderState{}
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
				if state, ok := states[varName]; ok && state.State != "live" {
					reportDeref(varName, state, expr.Span)
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
			case "short_var":
				checkExpr(stmt.Value)
				if helper, ok := xdpPacketHeaderCall(stmt.Value); ok {
					states[stmt.Name] = packetHeaderState{Helper: helper, State: "maybe_nil"}
				}
			case "assign":
				checkExpr(stmt.Target)
				checkExpr(stmt.Value)
			case "expr":
				checkExpr(stmt.Expr)
			case "return":
				checkExpr(stmt.Value)
			case "if":
				checkExpr(stmt.Cond)
				if varName, ok := nilComparedVar(stmt.Cond, "=="); ok {
					branchStates := clonePacketHeaderStates(states)
					if state, ok := branchStates[varName]; ok && state.State == "maybe_nil" {
						state.State = "nil"
						branchStates[varName] = state
					}
					oldStates := states
					states = branchStates
					walk(stmt.Then)
					thenStates := states
					states = oldStates
					if len(stmt.Else) > 0 {
						elseStates := clonePacketHeaderStates(oldStates)
						if state, ok := elseStates[varName]; ok && state.State == "maybe_nil" {
							state.State = "live"
							elseStates[varName] = state
						}
						states = elseStates
						walk(stmt.Else)
						elseStates = states
						states = oldStates
						if branchAlwaysReturns(stmt.Then) {
							states = elseStates
						} else if branchAlwaysReturns(stmt.Else) {
							states = thenStates
						}
						break
					}
					if branchAlwaysReturns(stmt.Then) {
						if state, ok := states[varName]; ok && state.State == "maybe_nil" {
							state.State = "live"
							states[varName] = state
						}
					}
					break
				}
				if varName, ok := nilComparedVar(stmt.Cond, "!="); ok {
					branchStates := clonePacketHeaderStates(states)
					if state, ok := branchStates[varName]; ok && state.State == "maybe_nil" {
						state.State = "live"
						branchStates[varName] = state
					}
					oldStates := states
					states = branchStates
					walk(stmt.Then)
					thenStates := states
					states = oldStates
					if len(stmt.Else) > 0 {
						elseStates := clonePacketHeaderStates(oldStates)
						if state, ok := elseStates[varName]; ok && state.State == "maybe_nil" {
							state.State = "nil"
							elseStates[varName] = state
						}
						states = elseStates
						walk(stmt.Else)
						elseStates = states
						states = oldStates
						if branchAlwaysReturns(stmt.Then) {
							states = elseStates
						} else if branchAlwaysReturns(stmt.Else) {
							states = thenStates
						}
						break
					}
					break
				}
				walk(stmt.Then)
				walk(stmt.Else)
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
