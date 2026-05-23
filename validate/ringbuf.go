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

type reserveState struct {
	Map   string
	State string
}

func ValidateRingbuf(program ir.Program) []diag.Diagnostic {
	ringMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf {
			ringMaps[m.Name] = m
		}
	}
	if len(ringMaps) == 0 {
		return nil
	}

	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if hasTypedStatements(fn) {
			diags = append(diags, validateTypedRingbuf(fn, ringMaps)...)
			continue
		}
		states := map[string]reserveState{}
		reportedMissingNil := map[string]bool{}
		for _, line := range bodyLines(fn) {
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
						diags = append(diags, missingNilCheck(fn, varName))
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
						diags = append(diags, missingNilCheck(fn, varName))
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

func validateTypedRingbuf(fn ir.Function, ringMaps map[string]ir.Map) []diag.Diagnostic {
	states := map[string]reserveState{}
	reportedMissingNil := map[string]bool{}
	reportedLive := map[string]bool{}
	var diags []diag.Diagnostic
	reportLive := func(varName string, primary span.Span) {
		if reportedLive[varName] {
			return
		}
		diags = append(diags, liveOnReturnAt(fn, varName, primary))
		reportedLive[varName] = true
	}
	checkWrite := func(varName string, primary span.Span) {
		state, ok := states[varName]
		if !ok {
			return
		}
		switch state.State {
		case "maybe_nil":
			if !reportedMissingNil[varName] {
				diags = append(diags, missingNilCheckAt(fn, varName, primary))
				reportedMissingNil[varName] = true
			}
		case "consumed":
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2103",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("write to ringbuf reservation %q after submit or discard", varName),
				Primary:  primary,
			})
		}
	}
	var walk func([]ir.Statement)
	walk = func(stmts []ir.Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var":
				if mapName, ok := reserveCall(stmt.Value); ok {
					if _, ok := ringMaps[mapName]; ok {
						states[stmt.Name] = reserveState{Map: mapName, State: "maybe_nil"}
					}
				}
			case "assign":
				if varName, ok := selectorBase(stmt.Target); ok {
					checkWrite(varName, stmt.Span)
				}
			case "expr":
				if mapName, op, varName, ok := consumeCall(stmt.Expr); ok {
					if _, ok := ringMaps[mapName]; !ok {
						break
					}
					state, ok := states[varName]
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
						if !reportedMissingNil[varName] {
							diags = append(diags, missingNilCheckAt(fn, varName, stmt.Span))
							reportedMissingNil[varName] = true
						}
						state.State = "consumed"
					case "consumed":
						diags = append(diags, diag.Diagnostic{
							Code:     "HZN2102",
							Severity: diag.SeverityError,
							Message:  fmt.Sprintf("ringbuf reservation %q is submitted or discarded more than once", varName),
							Primary:  stmt.Span,
						})
					case "nil":
						diags = append(diags, diag.Diagnostic{
							Code:     "HZN2105",
							Severity: diag.SeverityError,
							Message:  fmt.Sprintf("nil ringbuf reservation %q cannot be submitted or discarded", varName),
							Primary:  stmt.Span,
						})
					default:
						state.State = "consumed"
					}
					states[varName] = state
					break
				}
				if varName, ok := helperWriteBase(stmt.Expr); ok {
					checkWrite(varName, stmt.Span)
				}
			case "if":
				if varName, ok := nilCheckedVar(stmt.Cond); ok {
					branchStates := cloneReserveStates(states)
					if state, ok := branchStates[varName]; ok && state.State == "maybe_nil" {
						state.State = "nil"
						branchStates[varName] = state
					}
					oldStates := states
					states = branchStates
					walk(stmt.Then)
					states = oldStates
					if branchAlwaysReturns(stmt.Then) {
						if state, ok := states[varName]; ok && state.State == "maybe_nil" {
							state.State = "live"
							states[varName] = state
						}
					}
					break
				}
				walk(stmt.Then)
			case "for":
				walk(stmt.Body)
			case "return":
				for varName, state := range states {
					if state.State == "live" || state.State == "maybe_nil" {
						reportLive(varName, stmt.Span)
					}
				}
			}
		}
	}
	walk(functionStatements(fn))
	for varName, state := range states {
		if state.State == "consumed" || state.State == "nil" {
			continue
		}
		reportLive(varName, fn.Span)
	}
	return diags
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
	case "current_comm":
		return addressSelectorBase(&expr.Args[0])
	default:
		return "", false
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

func nilCheckedVar(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "binary" || expr.Op != "==" {
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

func branchAlwaysReturns(stmts []ir.Statement) bool {
	if len(stmts) == 0 {
		return false
	}
	last := stmts[len(stmts)-1]
	if last.Kind == "return" {
		return true
	}
	if last.Kind == "if" && branchAlwaysReturns(last.Then) {
		return true
	}
	return false
}
