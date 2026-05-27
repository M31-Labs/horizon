package validate

import "m31labs.dev/horizon/ir"

// aliasGraph maps an alias name to its root binding within a single function.
// The root is the original `x := <interesting-call>()` introduction; an alias
// is `y := x` (short_var with an ident RHS pointing at a tracked name).
// Lookup chases the chain transitively until a non-alias name is reached.
//
// Phase 1 scope: intra-function only. Cross-function alias tracking is
// deferred to v0.2 Phase 2 #13 (maple).
//
// v0.3 #6 extension: in addition to ident copies, the graph now tracks
// struct-field stores (`container.slot = event`) via fieldParent. The field
// store records the source ident's root so later reads through the same
// selector (`container.slot`) resolve back to the original tracked name.
// Field-store edges are intra-function only (cross-function field aliasing
// remains a deferred debt — see Acknowledged debts in the v0.3 Phase 1
// plan).
//
// Out-of-scope debts:
//   - Cross-function struct-field aliasing (helper writes a field of a
//     passed-in container) — deferred to a future maple-style task.
//   - Aliasing through pointer-of-pointer (`p := &x`) — not legal in Horizon
//     today; deferred.
//   - Escape detection fires only from `case "expr"` statements. Calls embedded
//     in `assign` RHS, `var_decl` RHS, `return`, or `if` conditions do NOT
//     trigger escape. HZN1447 in types/ blocks the source-syntax that could
//     reach these forms in real .hzn programs, so this is acceptable for Phase 1.
//     Phase 2 #13 (maple) should extend escape detection to cover all
//     call-expression contexts when HZN1447 is relaxed for helper-arg passes.
type aliasGraph struct {
	parent      map[string]string   // alias name -> immediate predecessor
	fieldParent map[fieldKey]string // (base, field) -> source ident
}

// fieldKey identifies a single struct-field slot inside a function scope.
// Nested-field aliasing (`event.inner.alias = x`) is NOT modeled: rootOfSelector
// only handles the one-deep `<base>.<field>` shape, mirroring the v0.3 plan's
// stated non-goal.
type fieldKey struct {
	Base  string
	Field string
}

func newAliasGraph() *aliasGraph {
	return &aliasGraph{
		parent:      map[string]string{},
		fieldParent: map[fieldKey]string{},
	}
}

// register records that `alias` is a copy of `source`. If `source` is itself
// an alias, the chain is preserved; root() chases it.
func (g *aliasGraph) register(alias string, source string) {
	if alias == "" || source == "" || alias == source {
		return
	}
	g.parent[alias] = source
}

// registerFieldStore records that `base.field = source` for later resolution
// by rootOfSelector. Empty names and self-edges are silently ignored to keep
// callers from having to guard at every site.
func (g *aliasGraph) registerFieldStore(base, field, source string) {
	if base == "" || field == "" || source == "" {
		return
	}
	g.fieldParent[fieldKey{Base: base, Field: field}] = source
}

// root returns the original binding name for `name`, chasing the alias chain.
// If `name` is not an alias, returns `name`. The function is safe against
// cycles (terminates after len(g.parent) steps).
func (g *aliasGraph) root(name string) string {
	seen := map[string]bool{}
	for {
		parent, ok := g.parent[name]
		if !ok || seen[name] {
			return name
		}
		seen[name] = true
		name = parent
	}
}

// fieldRoot returns the original tracked binding behind a field store, or ""
// if no field edge was registered for (base, field). The chase is guarded
// against cycles by an explicit step bound (len(fieldParent)) — a cycle would
// require two field stores in the same scope rebinding the same slot back
// onto each other through the alias chain, which is not reachable from any
// legal IR shape today, but the bound is cheap defense in depth.
func (g *aliasGraph) fieldRoot(base, field string) string {
	src, ok := g.fieldParent[fieldKey{Base: base, Field: field}]
	if !ok {
		return ""
	}
	// Chase the ident-alias chain forward to the original root. root() already
	// terminates after len(g.parent) steps; the field-edge layer is one hop
	// before that, so no extra bound is needed at this layer.
	return g.root(src)
}

// rootOfSelector resolves a one-deep `<base>.<field>` selector expression to
// its registered field-store root, or "" if either the expression is not a
// recognized selector or no field-store edge has been registered. Callers can
// fall through to their existing ident-resolution path when "" is returned.
func (g *aliasGraph) rootOfSelector(expr *ir.Expr) string {
	if expr == nil || expr.Kind != "selector" || expr.Operand == nil || expr.Operand.Kind != "ident" {
		return ""
	}
	return g.fieldRoot(expr.Operand.Name, expr.Field)
}

// aliasOf reports the source identifier on the RHS of a `y := x` short_var,
// or "" if stmt is not such a copy.
func aliasOf(stmt ir.Statement) string {
	if stmt.Kind != "short_var" || stmt.Value == nil || stmt.Value.Kind != "ident" {
		return ""
	}
	return stmt.Value.Name
}
