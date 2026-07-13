package validate

import (
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

// AnalyzeLSMScope proves that every deny return is dominated by a successful
// CellScope lookup keyed by the current cgroup. A mere helper mention is not
// sufficient: the lookup miss branch must return lsm.Allow before execution
// can reach a deny.
func AnalyzeLSMScope(program ir.Program) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, function := range program.Functions {
		if function.Section.Kind != ir.ProgramLSM {
			continue
		}
		state := scopeState{cgroupVars: map[string]bool{}, scopeVars: map[string]bool{}}
		diagnostics = append(diagnostics, analyzeScopeStatements(function, flatten(function.Body), state)...)
	}
	return diagnostics
}

type scopeState struct {
	cgroupVars map[string]bool
	scopeVars  map[string]bool
	guarded    bool
}

func analyzeScopeStatements(function ir.Function, statements []ir.Statement, state scopeState) []diag.Diagnostic {
	var diagnostics []diag.Diagnostic
	for _, statement := range statements {
		switch statement.Kind {
		case "short_var", "var_decl":
			if isCurrentCgroupCall(statement.Value) {
				state.cgroupVars[statement.Name] = true
			}
			if isCellScopeLookup(statement.Value, state.cgroupVars) {
				state.scopeVars[statement.Name] = true
			}
		case "return":
			if irQualifiedName(statement.Value) == "lsm.Deny" && !state.guarded {
				diagnostics = append(diagnostics, diag.Diagnostic{
					Code: "HZN1497", Severity: diag.SeverityError,
					Message: fmt.Sprintf("deny-capable LSM program %q is not cgroup-scoped", function.Name),
					Primary: statement.Span,
					Suggest: "look up bpf.current_cgroup_id() in CellScope and return lsm.Allow on a lookup miss before any deny",
				})
			}
		case "if":
			if scopeVar, equalsNil, ok := nilScopeCondition(statement.Cond, state.scopeVars); ok {
				_ = scopeVar
				if equalsNil && blockReturnsAllow(statement.Then) {
					diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Then, cloneScopeState(state))...)
					state.guarded = true
					if len(statement.Else) > 0 {
						branch := cloneScopeState(state)
						branch.guarded = true
						diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Else, branch)...)
					}
					continue
				}
				if !equalsNil {
					branch := cloneScopeState(state)
					branch.guarded = true
					diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Then, branch)...)
					diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Else, cloneScopeState(state))...)
					continue
				}
			}
			diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Then, cloneScopeState(state))...)
			diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Else, cloneScopeState(state))...)
		case "for":
			diagnostics = append(diagnostics, analyzeScopeStatements(function, statement.Body, cloneScopeState(state))...)
		case "switch":
			for _, branch := range statement.Cases {
				diagnostics = append(diagnostics, analyzeScopeStatements(function, branch.Body, cloneScopeState(state))...)
			}
		}
	}
	return diagnostics
}

func flatten(blocks []ir.Block) []ir.Statement {
	var statements []ir.Statement
	for _, block := range blocks {
		statements = append(statements, block.Statements...)
	}
	return statements
}

func cloneScopeState(state scopeState) scopeState {
	clone := scopeState{guarded: state.guarded, cgroupVars: map[string]bool{}, scopeVars: map[string]bool{}}
	for name, value := range state.cgroupVars {
		clone.cgroupVars[name] = value
	}
	for name, value := range state.scopeVars {
		clone.scopeVars[name] = value
	}
	return clone
}

func isCurrentCgroupCall(expression *ir.Expr) bool {
	return expression != nil && expression.Kind == "call" && irQualifiedName(expression.Func) == "bpf.current_cgroup_id"
}

func isCellScopeLookup(expression *ir.Expr, cgroupVars map[string]bool) bool {
	if expression == nil || expression.Kind != "call" || irQualifiedName(expression.Func) != "CellScope.lookup" || len(expression.Args) != 1 {
		return false
	}
	argument := &expression.Args[0]
	return isCurrentCgroupCall(argument) || argument.Kind == "ident" && cgroupVars[argument.Name]
}

func nilScopeCondition(condition *ir.Expr, scopeVars map[string]bool) (string, bool, bool) {
	if condition == nil || condition.Kind != "binary" || condition.Op != "==" && condition.Op != "!=" {
		return "", false, false
	}
	if condition.Left != nil && condition.Left.Kind == "ident" && scopeVars[condition.Left.Name] && condition.Right != nil && condition.Right.Kind == "nil" {
		return condition.Left.Name, condition.Op == "==", true
	}
	if condition.Right != nil && condition.Right.Kind == "ident" && scopeVars[condition.Right.Name] && condition.Left != nil && condition.Left.Kind == "nil" {
		return condition.Right.Name, condition.Op == "==", true
	}
	return "", false, false
}

func blockReturnsAllow(statements []ir.Statement) bool {
	if len(statements) == 0 {
		return false
	}
	last := statements[len(statements)-1]
	return last.Kind == "return" && irQualifiedName(last.Value) == "lsm.Allow"
}
