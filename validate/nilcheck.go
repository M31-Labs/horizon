package validate

import "m31labs.dev/horizon/ir"

// nilEqualityVar returns the identifier name and true if expr is a simple
// binary nil comparison of the form:
//
//	ident == nil   (op == "==")
//	nil == ident
//	ident != nil   (op == "!=")
//	nil != ident
//
// It does not recurse into && or || — callers that need conjunction handling
// should use nilCheckedVars or nilComparedVars instead.
func nilEqualityVar(expr *ir.Expr, op string) (string, bool) {
	if expr == nil || expr.Kind != "binary" || expr.Op != op {
		return "", false
	}
	if expr.Left != nil && expr.Left.Kind == "ident" &&
		expr.Right != nil && expr.Right.Kind == "nil" {
		return expr.Left.Name, true
	}
	if expr.Right != nil && expr.Right.Kind == "ident" &&
		expr.Left != nil && expr.Left.Kind == "nil" {
		return expr.Right.Name, true
	}
	return "", false
}

// nilComparedVars returns all variable names that are compared with op against
// nil in expr, recognising both simple equality (ident op nil) and &&-chained
// conjunctions where every leaf is an op-vs-nil check.
//
// It explicitly does NOT recurse into || disjunctions: only one disjunct of
// a || expression may hold at runtime, so no individual variable can be
// promoted as definitely nil-checked across the full ||.
func nilComparedVars(expr *ir.Expr, op string) []string {
	if expr == nil {
		return nil
	}
	// Simple case: direct binary comparison against nil.
	if name, ok := nilEqualityVar(expr, op); ok {
		return []string{name}
	}
	// &&-conjunction: both halves' nil-check facts compose.
	if expr.Kind == "binary" && expr.Op == "&&" {
		left := nilComparedVars(expr.Left, op)
		right := nilComparedVars(expr.Right, op)
		return append(left, right...)
	}
	// Everything else (including ||) yields no promotable variables.
	return nil
}

// nilCheckedVars returns all variable names that are proved == nil (i.e.,
// definitely nil) by the condition expr in a then-arm entered when the
// condition is true.  This is the plural form of the legacy nilCheckedVar
// helper: it recognises `x == nil`, `nil == x`, and &&-chains thereof.
//
// Use this when branching into the "nil" arm (if x == nil { ... }).
func nilCheckedVars(expr *ir.Expr) []string {
	return nilComparedVars(expr, "==")
}
