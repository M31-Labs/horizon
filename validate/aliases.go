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
// Out-of-scope debts:
//   - Aliasing through struct fields (`event.alias = x`) — not in any existing
//     fixture; deferred to v0.3.
//   - Aliasing through pointer-of-pointer (`p := &x`) — not legal in Horizon
//     today; deferred.
type aliasGraph struct {
	parent map[string]string // alias name -> immediate predecessor
}

func newAliasGraph() *aliasGraph {
	return &aliasGraph{parent: map[string]string{}}
}

// register records that `alias` is a copy of `source`. If `source` is itself
// an alias, the chain is preserved; root() chases it.
func (g *aliasGraph) register(alias string, source string) {
	if alias == "" || source == "" || alias == source {
		return
	}
	g.parent[alias] = source
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

// aliasOf reports the source identifier on the RHS of a `y := x` short_var,
// or "" if stmt is not such a copy.
func aliasOf(stmt ir.Statement) string {
	if stmt.Kind != "short_var" || stmt.Value == nil || stmt.Value.Kind != "ident" {
		return ""
	}
	return stmt.Value.Name
}
