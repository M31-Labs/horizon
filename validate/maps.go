package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func ValidateMaps(program ir.Program) []diag.Diagnostic {
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
		case ir.MapKindHash, ir.MapKindArray:
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
	}
	diags = append(diags, validateMapLookups(program)...)
	return diags
}

type lookupState struct {
	Source string
	Label  string
	State  string
}

func validateMapLookups(program ir.Program) []diag.Diagnostic {
	lookupMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindHash || m.Kind == ir.MapKindArray {
			lookupMaps[m.Name] = m
		}
	}
	if len(lookupMaps) == 0 {
		return nil
	}
	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if !hasTypedStatements(fn) {
			continue
		}
		diags = append(diags, validateTypedMapLookups(fn, lookupMaps)...)
	}
	return diags
}

func validateTypedMapLookups(fn ir.Function, lookupMaps map[string]ir.Map) []diag.Diagnostic {
	states := map[string]lookupState{}
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
				if mapName, ok := mapLookupCall(stmt.Value); ok {
					if _, ok := lookupMaps[mapName]; ok {
						states[stmt.Name] = lookupState{Source: mapName, Label: "map lookup result", State: "maybe_nil"}
					}
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
					branchStates := cloneLookupStates(states)
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
						elseStates := cloneLookupStates(oldStates)
						if state, ok := elseStates[varName]; ok && state.State == "maybe_nil" {
							state.State = "live"
							elseStates[varName] = state
						}
						states = elseStates
						walk(stmt.Else)
						elseStates = states
						states = mergeLookupBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
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
					branchStates := cloneLookupStates(states)
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
						elseStates := cloneLookupStates(oldStates)
						if state, ok := elseStates[varName]; ok && state.State == "maybe_nil" {
							state.State = "nil"
							elseStates[varName] = state
						}
						states = elseStates
						walk(stmt.Else)
						elseStates = states
						states = mergeLookupBranchStates(thenStates, elseStates, branchAlwaysReturns(stmt.Then), branchAlwaysReturns(stmt.Else))
						break
					}
					break
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

func nilGuardSuggestion(fn ir.Function, varName string) string {
	if fn.Section.Kind == ir.ProgramXDP {
		return fmt.Sprintf("if %s == nil { return xdp.Pass }", varName)
	}
	if fn.Section.Kind == ir.ProgramTC {
		return fmt.Sprintf("if %s == nil { return tc.OK }", varName)
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

func nilComparedVar(expr *ir.Expr, op string) (string, bool) {
	if expr == nil || expr.Kind != "binary" || expr.Op != op {
		return "", false
	}
	if expr.Left != nil && expr.Left.Kind == "ident" && expr.Right != nil && expr.Right.Kind == "nil" {
		return expr.Left.Name, true
	}
	if expr.Right != nil && expr.Right.Kind == "ident" && expr.Left != nil && expr.Left.Kind == "nil" {
		return expr.Right.Name, true
	}
	return "", false
}

func cloneLookupStates(in map[string]lookupState) map[string]lookupState {
	out := make(map[string]lookupState, len(in))
	for k, v := range in {
		out[k] = v
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
	if a == b {
		return a
	}
	return "maybe_nil"
}
