// Package-level helper-effect summarization for cross-call resource tracking.
//
// This module belongs to maple's Phase 2 #13 (helpers-take-resources) work.
// It is built ONCE per program by validate.Program and consumed by the
// ringbuf/maps/packet validators when they encounter a user-helper call that
// passes a tracked resource argument. The substrate replaces Phase 1's
// blanket "escaped" fallback with a precise transition derived from the
// helper body itself.
//
// Scope note: this file is maple's INTERNAL summary about USER helpers
// (sectionless functions written in .hzn source). It is intentionally
// distinct from oak's LookupHelperEffects API, which classifies
// compiler-known kernel helpers (bpf.*, Events.submit, xdp.eth, etc.) by
// matching against a static table. The two are separate concerns:
//
//   - oak: "does Events.submit consume its argument?" (yes, by definition)
//   - maple: "does user-helper record(ev) consume ev?" (walk the body)
//
// They do not call each other and they do not share types.
package validate

import "m31labs.dev/horizon/ir"

// HelperEffect describes what a user helper does to one parameter on every
// path through its body. The lattice mirrors the language of the per-state-
// machine validators (live/consumed/escaped/maybe_consumed).
type HelperEffect int

const (
	// HelperEffectUnknown is the bottom of the lattice: the helper could not
	// be summarized (depth limit hit, cycle in the call-graph, body not
	// analyzable). Callers must fall back to Phase 1 behavior — treat the
	// argument as "escaped" and suppress downstream diagnostics on both
	// branches.
	HelperEffectUnknown HelperEffect = iota
	// HelperEffectPreserves means the helper provably does NOT consume the
	// argument on any path: no submit/discard call, no field write, no
	// further escape. Caller's state machine is left unchanged.
	HelperEffectPreserves
	// HelperEffectConsumes means the helper definitely consumes the argument
	// on every path (submit, discard, or dereference). Caller transitions
	// from live to consumed.
	HelperEffectConsumes
	// HelperEffectMixed means different paths produce different effects
	// (one branch submits, another returns without). Caller transitions
	// from live to maybe_consumed.
	HelperEffectMixed
	// HelperEffectEscapes means the helper's body passes the value to ANOTHER
	// call that itself escapes (unknown user helper, indirect call). Caller
	// falls back to the Phase 1 "escaped" suppression.
	HelperEffectEscapes
)

// maxHelperEffectDepth caps the helper-call-chain depth that the summary
// builder will follow. Acyclicity of the helper call graph is guaranteed by
// HZN1503 (types/checker.go::validateFunctionCallGraph), so this is defense
// in depth — it bounds work and protects against any future cycle defense
// gap. Matches the verifier's tail-call depth limit.
const maxHelperEffectDepth = 8

// HelperEffects is the program-level summary keyed by helper name. Each
// helper carries one HelperEffect per parameter position. Non-resource
// parameters are summarized as HelperEffectPreserves (the caller would
// never apply a transition to a scalar anyway, but the explicit value keeps
// callers honest).
type HelperEffects struct {
	byName map[string][]HelperEffect
}

// EffectFor returns the effect for the named helper at parameter index i.
// If the helper is not known (compiler-known kernel helper, or the program
// has no such function), or the index is out of range, the result is
// HelperEffectUnknown so callers fall back conservatively.
func (e HelperEffects) EffectFor(helper string, paramIndex int) HelperEffect {
	if e.byName == nil {
		return HelperEffectUnknown
	}
	effects, ok := e.byName[helper]
	if !ok {
		return HelperEffectUnknown
	}
	if paramIndex < 0 || paramIndex >= len(effects) {
		return HelperEffectUnknown
	}
	return effects[paramIndex]
}

// BuildHelperEffects walks every user helper (sectionless function) in the
// program once, topologically sorting them by call-graph so that a helper
// calling another helper sees the callee's summary already computed. Returns
// a HelperEffects with one entry per user helper. Entrypoints (functions
// with a non-empty Section.Kind) are NOT summarized — they are never call
// targets in Horizon today.
//
// If the call graph contains a cycle (which HZN1503 should prevent), every
// helper is summarized as all-Unknown. This is sound: callers fall back to
// the Phase 1 "escaped" behavior.
func BuildHelperEffects(program ir.Program) HelperEffects {
	helpers := userHelpers(program)
	order, ok := topoSortHelpers(helpers)
	if !ok {
		// Cycle detected — defensive fallback. Summarize every helper as
		// all-Unknown so callers behave exactly as Phase 1 did.
		effects := make(map[string][]HelperEffect, len(helpers))
		for _, fn := range helpers {
			vec := make([]HelperEffect, len(fn.Params))
			for i := range vec {
				vec[i] = HelperEffectUnknown
			}
			effects[fn.Name] = vec
		}
		return HelperEffects{byName: effects}
	}
	// Compute depth-from-leaf for every helper. Leaves (helpers that call no
	// other user helper) sit at depth 1; an interior helper sits one above the
	// max depth of any user-helper callee it reaches. Topo order guarantees
	// every callee's depth is known before the caller is visited. Helpers
	// whose depth exceeds maxHelperEffectDepth are summarized as all-Unknown
	// so callers fall back to Phase 1 "escaped" behavior. This is defense in
	// depth: HZN1503 already prevents recursion, so an acyclic chain longer
	// than the limit is the only way to trip this — pathological but bounded.
	depthOf := make(map[string]int, len(order))
	byNameLookup := make(map[string]*ir.Function, len(order))
	for _, fn := range order {
		byNameLookup[fn.Name] = fn
	}
	for _, fn := range order {
		max := 0
		for _, called := range calledHelperNames(fn) {
			if _, ok := byNameLookup[called]; !ok {
				continue
			}
			if d := depthOf[called]; d > max {
				max = d
			}
		}
		depthOf[fn.Name] = max + 1
	}
	effects := HelperEffects{byName: make(map[string][]HelperEffect, len(order))}
	for _, fn := range order {
		if depthOf[fn.Name] > maxHelperEffectDepth {
			vec := make([]HelperEffect, len(fn.Params))
			for i := range vec {
				vec[i] = HelperEffectUnknown
			}
			effects.byName[fn.Name] = vec
			continue
		}
		effects.byName[fn.Name] = summarizeHelper(*fn, effects, 0)
	}
	return effects
}

// userHelpers returns every sectionless function (i.e., not an entrypoint).
// Returns pointers into the program's Functions slice so callers can compare
// by identity, though identity is not load-bearing here — name-keying is the
// public contract.
func userHelpers(program ir.Program) []*ir.Function {
	var out []*ir.Function
	for i := range program.Functions {
		fn := &program.Functions[i]
		if fn.Section.Kind == "" {
			out = append(out, fn)
		}
	}
	return out
}

// topoSortHelpers returns helpers in callee-first order (each helper appears
// after every helper it calls). On cycle, returns (nil, false).
func topoSortHelpers(helpers []*ir.Function) ([]*ir.Function, bool) {
	byName := make(map[string]*ir.Function, len(helpers))
	for _, fn := range helpers {
		byName[fn.Name] = fn
	}
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int, len(helpers))
	var order []*ir.Function
	var visit func(*ir.Function) bool
	visit = func(fn *ir.Function) bool {
		switch state[fn.Name] {
		case visiting:
			return false // cycle
		case visited:
			return true
		}
		state[fn.Name] = visiting
		for _, called := range calledHelperNames(fn) {
			callee, ok := byName[called]
			if !ok {
				// Call to an unknown name (compiler-known helper, undefined,
				// out-of-program). Skip; the effect lookup handles it.
				continue
			}
			if !visit(callee) {
				return false
			}
		}
		state[fn.Name] = visited
		order = append(order, fn)
		return true
	}
	for _, fn := range helpers {
		if !visit(fn) {
			return nil, false
		}
	}
	return order, true
}

// summarizeHelper returns the per-parameter effect vector for fn. Each
// parameter is analyzed independently. depth bounds how far the summary
// builder will recurse through the call-graph — exceeding it returns
// all-Unknown for fn (callers fall back to "escaped").
func summarizeHelper(fn ir.Function, known HelperEffects, depth int) []HelperEffect {
	out := make([]HelperEffect, len(fn.Params))
	if depth > maxHelperEffectDepth {
		for i := range out {
			out[i] = HelperEffectUnknown
		}
		return out
	}
	for i, param := range fn.Params {
		if !param.Resource {
			// Non-resource params never need a tracked transition; the caller
			// would not apply one anyway. Mark as Preserves to be explicit.
			out[i] = HelperEffectPreserves
			continue
		}
		out[i] = analyzeParamEffect(fn, param.Name, known, depth)
	}
	return out
}

// analyzeParamEffect walks fn's body tracking whether paramName is consumed,
// preserved, or escaped on any path, then compresses the per-path flags into
// a single HelperEffect via the lattice merge rule:
//
//	consumed && preserved → Mixed
//	consumed only         → Consumes
//	preserved only        → Preserves
//	escaped               → Escapes (dominates the consumed/preserved axes)
//	unknown               → Unknown (dominates Escapes — most conservative)
//
// "Escaped" here means the helper passed the value to ANOTHER call whose
// summary is itself Escapes or Unknown — i.e., we cannot trust either side
// of the lattice for the deeper callee.
func analyzeParamEffect(fn ir.Function, paramName string, known HelperEffects, depth int) HelperEffect {
	flags := paramEffectFlags{}
	aliases := newAliasGraph()
	for _, block := range fn.Body {
		walkParamEffectStatements(block.Statements, paramName, aliases, known, depth, &flags)
	}
	// #6 (B2) field-store escape rule (plan Q2): if the helper stored its
	// tracked param into a container field and that field was NOT later
	// consumed downstream (no submit / discard / deref through the field
	// alias), the param's downstream fate inside the container is opaque to
	// intra-function analysis. Widen to escaped (sound conservative). The
	// alternative — threading the container's caller through the field — is
	// the deferred cross-function struct-field aliasing debt.
	if !flags.consumed {
		for _, src := range aliases.fieldParent {
			if aliases.root(src) == paramName {
				flags.escaped = true
				break
			}
		}
	}
	return flags.compress()
}

// paramEffectFlags accumulates the disjunction of effects observed on the
// paths through a helper body. Each flag is monotonic — once set, it stays.
type paramEffectFlags struct {
	consumed  bool
	preserved bool
	escaped   bool
	unknown   bool
}

func (f *paramEffectFlags) compress() HelperEffect {
	if f.unknown {
		return HelperEffectUnknown
	}
	if f.escaped {
		return HelperEffectEscapes
	}
	if f.consumed && f.preserved {
		return HelperEffectMixed
	}
	if f.consumed {
		return HelperEffectConsumes
	}
	if f.preserved {
		return HelperEffectPreserves
	}
	// Body never references the parameter at all — treat as preserved (the
	// helper trivially does not consume it).
	return HelperEffectPreserves
}

func walkParamEffectStatements(stmts []ir.Statement, paramName string, aliases *aliasGraph, known HelperEffects, depth int, flags *paramEffectFlags) {
	for _, stmt := range stmts {
		walkParamEffectStatement(stmt, paramName, aliases, known, depth, flags)
	}
}

func walkParamEffectStatement(stmt ir.Statement, paramName string, aliases *aliasGraph, known HelperEffects, depth int, flags *paramEffectFlags) {
	switch stmt.Kind {
	case "short_var":
		// `alias := param` — register the alias so later references resolve.
		if src := aliasOf(stmt); src != "" && aliases.root(src) == paramName {
			aliases.register(stmt.Name, src)
		}
		// Recurse into the RHS expression to catch consume/escape there.
		walkParamEffectExpr(stmt.Value, paramName, aliases, known, depth, flags)
		// Also recurse if the RHS itself is a non-ident (e.g. a call).
		if !flags.preserved {
			flags.preserved = false // no-op; preserved is set by return-without-use compression
		}
	case "var_decl":
		walkParamEffectExpr(stmt.Value, paramName, aliases, known, depth, flags)
	case "assign":
		// `param.field = ...` — writing through the param dereferences it.
		if base, ok := selectorBase(stmt.Target); ok && aliases.root(base) == paramName {
			flags.consumed = true
		}
		// #6 field-store aliasing: when `container.slot = paramAlias` is seen
		// and paramAlias roots to the analyzed param, register the field edge
		// so later reads through that selector (e.g. `Events.submit(c.slot)`)
		// resolve back to the param's root via rootOfSelector. We deliberately
		// skip walking stmt.Value through case 5 (ident → preserved) in this
		// shape — the store is a "move into container", not a "use as value",
		// so flagging preserved would spuriously force Mixed when the field is
		// later consumed. The field-store itself is widened to escaped at the
		// end of analyzeParamEffect IF the field was never consumed downstream.
		isFieldStoreOfParam := false
		if stmt.Target != nil && stmt.Target.Kind == "selector" &&
			stmt.Target.Operand != nil && stmt.Target.Operand.Kind == "ident" &&
			stmt.Value != nil && stmt.Value.Kind == "ident" &&
			aliases.root(stmt.Value.Name) == paramName {
			aliases.registerFieldStore(stmt.Target.Operand.Name, stmt.Target.Field, stmt.Value.Name)
			isFieldStoreOfParam = true
		}
		// For the field-store-of-param shape, skip walking BOTH target and
		// value: walking the target after registering the edge would cause
		// case 3 (selector deref) to spuriously fire `consumed` because the
		// selector now roots to paramName via the just-registered field edge.
		// Walking the value would spuriously fire `preserved` for the same
		// reason described in the registerFieldStore comment above. Any nested
		// escapes inside the container ident (e.g. `c.subfield = ev`) would
		// require nested-field handling, which is an acknowledged debt.
		if !isFieldStoreOfParam {
			walkParamEffectExpr(stmt.Target, paramName, aliases, known, depth, flags)
			walkParamEffectExpr(stmt.Value, paramName, aliases, known, depth, flags)
		}
	case "expr":
		walkParamEffectExpr(stmt.Expr, paramName, aliases, known, depth, flags)
	case "return":
		walkParamEffectExpr(stmt.Value, paramName, aliases, known, depth, flags)
	case "if":
		if stmt.Init != nil {
			walkParamEffectStatement(*stmt.Init, paramName, aliases, known, depth, flags)
		}
		walkParamEffectExpr(stmt.Cond, paramName, aliases, known, depth, flags)
		// Walk then/else with separate flag snapshots so a divergence between
		// branches produces Mixed at the join point.
		thenFlags := *flags
		walkParamEffectStatements(stmt.Then, paramName, aliases, known, depth, &thenFlags)
		elseFlags := *flags
		walkParamEffectStatements(stmt.Else, paramName, aliases, known, depth, &elseFlags)
		mergeBranchFlags(flags, thenFlags, elseFlags)
	case "for":
		if stmt.Init != nil {
			walkParamEffectStatement(*stmt.Init, paramName, aliases, known, depth, flags)
		}
		walkParamEffectExpr(stmt.Cond, paramName, aliases, known, depth, flags)
		if stmt.Post != nil {
			walkParamEffectStatement(*stmt.Post, paramName, aliases, known, depth, flags)
		}
		walkParamEffectStatements(stmt.Body, paramName, aliases, known, depth, flags)
	case "switch":
		walkParamEffectExpr(stmt.Cond, paramName, aliases, known, depth, flags)
		for _, c := range stmt.Cases {
			walkParamEffectStatements(c.Body, paramName, aliases, known, depth, flags)
		}
	}
}

// mergeBranchFlags joins per-branch flag snapshots back into the parent
// frame. Any flag set on at least one branch is set on the parent. Mixed
// emerges naturally from `consumed_on_one_branch || preserved_on_other`
// once compress() runs.
func mergeBranchFlags(parent *paramEffectFlags, thenF, elseF paramEffectFlags) {
	parent.consumed = parent.consumed || thenF.consumed || elseF.consumed
	parent.escaped = parent.escaped || thenF.escaped || elseF.escaped
	parent.unknown = parent.unknown || thenF.unknown || elseF.unknown
	// Preserved fires when a branch references the param without consuming
	// or escaping it. Track per-branch and OR.
	parent.preserved = parent.preserved || thenF.preserved || elseF.preserved
}

func walkParamEffectExpr(expr *ir.Expr, paramName string, aliases *aliasGraph, known HelperEffects, depth int, flags *paramEffectFlags) {
	if expr == nil {
		return
	}
	// 1. Compiler-known consume: Events.submit(param) / Events.discard(param).
	//    Uses consumeCallResolved so selector-form args (`Events.submit(c.slot)`)
	//    resolve through the field-store alias graph (#6) back to the original
	//    tracked root. Fully classified at this level; do NOT recurse into the
	//    call's parts (the arg-ident would otherwise also register as
	//    "preserved" in case 6, double-counting the same syntactic occurrence).
	if _, _, argName, ok := consumeCallResolved(expr, aliases); ok {
		if aliases.root(argName) == paramName {
			flags.consumed = true
		}
		return
	}
	// 2. Compiler-known helper write that touches param
	//    (bpf.current_comm(&param.field)). The param is reached through
	//    selector+unary inside Args[0]; we still recurse into other Args so a
	//    write doesn't mask deeper escapes there.
	if base, ok := helperWriteBase(expr); ok && aliases.root(base) == paramName {
		flags.consumed = true
		for i := 1; i < len(expr.Args); i++ {
			walkParamEffectExpr(&expr.Args[i], paramName, aliases, known, depth, flags)
		}
		return
	}
	// 3. Dereference of param via selector (param.field). This consumes the
	//    nullable handle at the use site; do NOT recurse into the operand
	//    (which is the param ident itself) — that would double-count as
	//    "preserved" in case 6. Also handle the #6 field-alias case where
	//    the selector reads from a container slot that was registered as a
	//    field-store of paramName (`container.slot` after `container.slot = ev`):
	//    the read still consumes the underlying tracked root.
	if expr.Kind == "selector" {
		if root := aliases.rootOfSelector(expr); root == paramName {
			flags.consumed = true
			return
		}
		if base, ok := selectorBase(expr); ok && aliases.root(base) == paramName {
			flags.consumed = true
			return
		}
	}
	// 4. User-helper call: param appears as an argument. Classify each arg
	//    via the callee's summary; do NOT recurse into Args (the arg-ident
	//    would otherwise register as "preserved" in case 6, masking the
	//    classified effect with a spurious preserved flag).
	if expr.Kind == "call" {
		if name := userHelperName(expr.Func); name != "" {
			for i, arg := range expr.Args {
				if arg.Kind != "ident" {
					// Non-ident arg: still recurse so nested expressions are
					// classified.
					walkParamEffectExpr(&expr.Args[i], paramName, aliases, known, depth, flags)
					continue
				}
				if aliases.root(arg.Name) != paramName {
					continue
				}
				switch known.EffectFor(name, i) {
				case HelperEffectConsumes:
					flags.consumed = true
				case HelperEffectPreserves:
					flags.preserved = true
				case HelperEffectMixed:
					flags.consumed = true
					flags.preserved = true
				case HelperEffectEscapes:
					flags.escaped = true
				default: // HelperEffectUnknown
					// Callee not in the program (compiler-known helpers go
					// through selector form, not bare ident; reaching here
					// means an undefined or out-of-program name). Fall back
					// to Unknown to preserve Phase 1 "escaped" behavior at
					// the caller.
					flags.unknown = true
				}
			}
			return
		}
	}
	// 5. Plain ident reference: `return param` or use-as-value without
	//    consuming. Mark preserved so a body that only references the param
	//    in a return expression compresses to Preserves.
	if expr.Kind == "ident" && aliases.root(expr.Name) == paramName {
		flags.preserved = true
		return
	}
	// 6. Recurse into children for any expression we did not classify above.
	walkParamEffectExpr(expr.Operand, paramName, aliases, known, depth, flags)
	walkParamEffectExpr(expr.Left, paramName, aliases, known, depth, flags)
	walkParamEffectExpr(expr.Right, paramName, aliases, known, depth, flags)
	walkParamEffectExpr(expr.Func, paramName, aliases, known, depth, flags)
	for i := range expr.Args {
		walkParamEffectExpr(&expr.Args[i], paramName, aliases, known, depth, flags)
	}
	for i := range expr.Fields {
		walkParamEffectExpr(&expr.Fields[i].Value, paramName, aliases, known, depth, flags)
	}
}

// userHelperName returns the bare name of a user-helper-style call target
// (a plain ident — no selector). Returns "" for compiler-known helpers
// (bpf.*, xdp.*, map methods) which always come through as selectors.
func userHelperName(expr *ir.Expr) string {
	if expr == nil || expr.Kind != "ident" {
		return ""
	}
	return expr.Name
}

// calledHelperNames returns the set of user-function names called directly
// from fn's body. Used by topoSortHelpers to build the dependency edges.
// Compiler-known helpers (bpf.*, Events.submit, xdp.eth) are filtered out
// because they always appear as selector targets, not bare idents.
func calledHelperNames(fn *ir.Function) []string {
	seen := map[string]bool{}
	var out []string
	var walkExpr func(*ir.Expr)
	var walkStmts func([]ir.Statement)
	walkExpr = func(expr *ir.Expr) {
		if expr == nil {
			return
		}
		if expr.Kind == "call" {
			if name := userHelperName(expr.Func); name != "" {
				if !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
		walkExpr(expr.Operand)
		walkExpr(expr.Left)
		walkExpr(expr.Right)
		walkExpr(expr.Func)
		for i := range expr.Args {
			walkExpr(&expr.Args[i])
		}
		for i := range expr.Fields {
			walkExpr(&expr.Fields[i].Value)
		}
	}
	var walkStmt func(ir.Statement)
	walkStmt = func(stmt ir.Statement) {
		walkExpr(stmt.Value)
		walkExpr(stmt.Expr)
		walkExpr(stmt.Cond)
		walkExpr(stmt.Target)
		if stmt.Init != nil {
			walkStmt(*stmt.Init)
		}
		if stmt.Post != nil {
			walkStmt(*stmt.Post)
		}
		walkStmts(stmt.Then)
		walkStmts(stmt.Else)
		walkStmts(stmt.Body)
		for _, c := range stmt.Cases {
			walkStmts(c.Body)
		}
	}
	walkStmts = func(stmts []ir.Statement) {
		for _, s := range stmts {
			walkStmt(s)
		}
	}
	for _, block := range fn.Body {
		walkStmts(block.Statements)
	}
	return out
}
