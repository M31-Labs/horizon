package validate

import "m31labs.dev/horizon/ir"

// polarity records which nil-comparison fact a recursive walk is seeking.
// "polEq" means callers want the set of idents proved == nil when the cond
// is true; "polNeq" means callers want the set proved != nil.
type polarity int

const (
	polEq polarity = iota
	polNeq
)

// flip returns the opposite polarity.
func (p polarity) flip() polarity {
	if p == polEq {
		return polNeq
	}
	return polEq
}

// opString renders the polarity as the matching binary operator.
func (p polarity) opString() string {
	if p == polEq {
		return "=="
	}
	return "!="
}

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
// conjunctions, plus their DeMorgan-equivalent shapes via `!`-negation.
//
// The walk threads an internal polarity flag that toggles per unary `!`.
// Public callers pass op ("==" or "!=") matching the fact they want proved
// when the condition is true; the polarity is initialised from op and stays
// in the "even" phase until a `!` flips it.
//
// Recognition lattice (each phase composes the leaf rule with one connective
// rule for `&&` and one for `||`):
//
//	┌──────────────┬───────────────────────────┬─────────────┬─────────────┐
//	│              │ leaf `ident OP nil`       │ binary `&&` │ binary `||` │
//	├──────────────┼───────────────────────────┼─────────────┼─────────────┤
//	│ even phase   │ singleton iff OP matches  │ union       │ empty       │
//	│ (cond true)  │ requested polarity        │             │             │
//	├──────────────┼───────────────────────────┼─────────────┼─────────────┤
//	│ odd phase    │ singleton iff OP is the   │ empty       │ union       │
//	│ (cond false, │ OPPOSITE of requested     │             │             │
//	│  under one `!`) │ polarity              │             │             │
//	└──────────────┴───────────────────────────┴─────────────┴─────────────┘
//
// Rationale: under even phase, `cond true ⇒ both halves of && true`, so `&&`
// composes facts but `||` cannot prove any single disjunct. Under odd phase
// we are reasoning about `cond false`, so the connectives flip: `cond false ⇔
// (a || b) false ⇔ both a and b false`, so `||` composes; `&&` cannot prove
// any single conjunct false. The leaf op-match flips because `cond false`
// inverts the proved fact: `x == nil` being false means `x != nil`.
//
// Two consecutive `!`s cancel by toggling the phase twice (a no-op).
func nilComparedVars(expr *ir.Expr, op string) []string {
	want := polEq
	if op == "!=" {
		want = polNeq
	}
	return nilComparedVarsPol(expr, want, false)
}

// nilComparedVarsPol is the polarity-threaded inner walker. `want` is the
// fact callers want proved; `flipped` is true when an odd number of `!`s
// have been traversed.
func nilComparedVarsPol(expr *ir.Expr, want polarity, flipped bool) []string {
	if expr == nil {
		return nil
	}

	// `!inner`: descend with the phase toggled.
	if expr.Kind == "unary" && expr.Op == "!" {
		return nilComparedVarsPol(expr.Operand, want, !flipped)
	}

	// Leaf: an ident-vs-nil binary. The matching op depends on phase.
	matchOp := want.opString()
	if flipped {
		matchOp = want.flip().opString()
	}
	if name, ok := nilEqualityVar(expr, matchOp); ok {
		return []string{name}
	}

	if expr.Kind == "binary" {
		switch expr.Op {
		case "&&":
			// Even phase: `&&` composes (both halves hold). Odd phase: `&&`
			// cannot prove anything about either half individually.
			if flipped {
				return nil
			}
			left := nilComparedVarsPol(expr.Left, want, flipped)
			right := nilComparedVarsPol(expr.Right, want, flipped)
			return append(left, right...)
		case "||":
			// Odd phase: `||` composes (both halves false under outer `!`).
			// Even phase: `||` cannot prove anything about either disjunct.
			if !flipped {
				return nil
			}
			left := nilComparedVarsPol(expr.Left, want, flipped)
			right := nilComparedVarsPol(expr.Right, want, flipped)
			return append(left, right...)
		}
	}
	// Anything else (helpers, arithmetic, unrecognised shapes) yields nothing.
	return nil
}

// nilCheckedVars returns all variable names that are proved == nil (i.e.,
// definitely nil) by the condition expr in a then-arm entered when the
// condition is true.  This is the plural form of the legacy nilCheckedVar
// helper: it recognises `x == nil`, `nil == x`, and &&-chains thereof, plus
// the DeMorgan-equivalent shapes via `!`-negation (see nilComparedVars).
//
// Use this when branching into the "nil" arm (if x == nil { ... }).
func nilCheckedVars(expr *ir.Expr) []string {
	return nilComparedVars(expr, "==")
}
