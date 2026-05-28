package validate

import "m31labs.dev/horizon/ir"

// Sites holds all typed IR sites of interest collected by a single pass over
// an ir.Program. Task 3b will migrate per-validator walks to consume this
// instead of each re-walking the tree independently.
type Sites struct {
	Loops               []LoopSite
	RingbufReserve      []RingbufReserveSite
	RingbufHelperReturn []RingbufHelperReturnSite
	MapLookup           []MapLookupSite
	HelperCall          []HelperCallSite
	PacketHeader        []PacketHeaderSite
	StackLocals         []StackLocalSite
}

// LoopSite is a for-statement.
type LoopSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
}

// RingbufReserveSite is a short_var whose RHS is a ringbuf.reserve() call.
type RingbufReserveSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
	MapName  string
}

// RingbufHelperReturnSite is a short_var whose RHS is a user-helper call
// whose target function has a resource-pointer return type. The validate-
// layer ringbuf walker consults HelperEffects.ReturnEffectFor at the call
// site to decide whether to bind the result as a tracked reservation
// (analogous to a RingbufReserveSite). v0.3 alder Phase 2 (roadmap #18).
//
// HelperName is the bare ident name of the called helper — used by
// validateTypedRingbuf to look up the ReturnEffect verdict.
type RingbufHelperReturnSite struct {
	Function   *ir.Function
	Stmt       *ir.Statement
	HelperName string
}

// MapLookupSite is a short_var whose RHS is a map.lookup() call on a
// non-ringbuf lookup map.
type MapLookupSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
	MapName  string
}

// HelperCallSite is a call expression whose target resolves to a bpf.* helper.
type HelperCallSite struct {
	Function *ir.Function
	Expr     *ir.Expr
}

// PacketHeaderSite is a short_var whose RHS is an xdp.{eth,ipv4,tcp,udp}
// call.
type PacketHeaderSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
	Helper   string
}

// StackLocalSite identifies a stack-local aggregate declaration. Collect
// flags three shapes:
//
//   - `var_decl` whose declared Type is an aggregate (struct or fixed-length
//     array). Type is taken from stmt.Type.
//   - `short_var` whose RHS is a literal `struct_lit`. Type is taken from the
//     struct_lit's Name.
//   - `short_var` whose RHS has an inferred aggregate type (e.g.
//     `event := makeEvent()` where makeEvent returns a struct by value, or
//     `arr := otherArr` where otherArr is a fixed-length array local). Type
//     is inferred via the same lookup as the stack estimator.
//
// Type carries the inferred ir.Type for downstream consumers (stack-byte
// accounting, future validators that key off stack-local declarations).
type StackLocalSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
	Type     ir.Type
}

// Collect performs a single typed IR traversal and returns all Sites found in
// the program. Only functions with typed statements are walked; functions using
// raw BodyText are skipped (they are handled by the legacy text-based validators
// until Task 3b consolidates them).
func Collect(program ir.Program) Sites {
	ringMaps := map[string]bool{}
	lookupMaps := map[string]bool{}
	for _, m := range program.Maps {
		switch {
		case m.Kind == ir.MapKindRingbuf:
			ringMaps[m.Name] = true
		case m.Kind.IsLookup():
			lookupMaps[m.Name] = true
		}
	}

	// Build a struct-name index + map-name → value type table so the
	// inferred-type pass (StackLocalSite for short_vars whose RHS returns
	// an aggregate by value) has the same shape catalog the stack estimator
	// uses. Functions are indexed by name to resolve call-return types.
	structs := map[string]ir.Struct{}
	for _, s := range program.Structs {
		structs[s.Name] = s
	}
	mapValues := map[string]ir.Type{}
	for _, m := range program.Maps {
		mapValues[m.Name] = m.Val
	}
	funcs := map[string]*ir.Function{}
	for i := range program.Functions {
		funcs[program.Functions[i].Name] = &program.Functions[i]
	}

	var sites Sites
	for i := range program.Functions {
		fn := &program.Functions[i]
		if !hasTypedStatements(*fn) {
			continue
		}
		// Per-function local-type environment seeded with params; used by
		// inferStackLocalType to resolve short_var RHS types for the
		// inferred-aggregate StackLocalSite case.
		locals := map[string]ir.Type{}
		for _, param := range fn.Params {
			locals[param.Name] = param.Type
		}
		ctx := &collectCtx{
			ringMaps:   ringMaps,
			lookupMaps: lookupMaps,
			structs:    structs,
			mapValues:  mapValues,
			funcs:      funcs,
			locals:     locals,
		}
		for j := range fn.Body {
			collectStmts(fn, fn.Body[j].Statements, ctx, &sites)
		}
	}
	return sites
}

// collectCtx threads program-level lookup tables and a per-function locals
// environment through the recursive collector. The locals map carries the
// inferred type of each short_var declaration so subsequent stack-local
// detection can resolve `event := someCall()` shapes the same way the
// stack estimator does.
type collectCtx struct {
	ringMaps   map[string]bool
	lookupMaps map[string]bool
	structs    map[string]ir.Struct
	mapValues  map[string]ir.Type
	funcs      map[string]*ir.Function
	locals     map[string]ir.Type
}

func collectStmts(fn *ir.Function, stmts []ir.Statement, ctx *collectCtx, sites *Sites) {
	for i := range stmts {
		collectStmt(fn, &stmts[i], ctx, sites)
	}
}

func collectStmt(fn *ir.Function, stmt *ir.Statement, ctx *collectCtx, sites *Sites) {
	switch stmt.Kind {
	case "for":
		sites.Loops = append(sites.Loops, LoopSite{Function: fn, Stmt: stmt})

	case "short_var":
		if mapName, ok := reserveCall(stmt.Value); ok && ctx.ringMaps[mapName] {
			sites.RingbufReserve = append(sites.RingbufReserve, RingbufReserveSite{
				Function: fn,
				Stmt:     stmt,
				MapName:  mapName,
			})
			ctx.locals[stmt.Name] = ptrToType(ctx.mapValues[mapName])
		} else if helperName, ok := userHelperReturningResource(stmt.Value, ctx); ok {
			// v0.3 alder Phase 2 (roadmap #18): short_var whose RHS is a
			// user-helper call that returns a resource pointer. The function
			// gets walked by AnalyzeRingbuf (alongside RingbufReserve-bearing
			// functions) so validateTypedRingbuf can bind the result as a
			// tracked reservation by consulting HelperEffects.ReturnEffectFor.
			sites.RingbufHelperReturn = append(sites.RingbufHelperReturn, RingbufHelperReturnSite{
				Function:   fn,
				Stmt:       stmt,
				HelperName: helperName,
			})
			// Seed locals with the return type so subsequent inference passes
			// (StackLocals, downstream short_vars) can resolve references.
			if calledFn, found := ctx.funcs[helperName]; found {
				ctx.locals[stmt.Name] = calledFn.Return
			}
		} else if mapName, ok := mapLookupCall(stmt.Value); ok && ctx.lookupMaps[mapName] {
			sites.MapLookup = append(sites.MapLookup, MapLookupSite{
				Function: fn,
				Stmt:     stmt,
				MapName:  mapName,
			})
			ctx.locals[stmt.Name] = ptrToType(ctx.mapValues[mapName])
		} else if helper, ok := xdpPacketHeaderCall(stmt.Value); ok {
			sites.PacketHeader = append(sites.PacketHeader, PacketHeaderSite{
				Function: fn,
				Stmt:     stmt,
				Helper:   helper,
			})
		} else if stmt.Value != nil && stmt.Value.Kind == "struct_lit" {
			typ := ir.Type{Name: stmt.Value.Name}
			sites.StackLocals = append(sites.StackLocals, StackLocalSite{
				Function: fn,
				Stmt:     stmt,
				Type:     typ,
			})
			ctx.locals[stmt.Name] = typ
		} else if typ, ok := inferStackLocalType(stmt.Value, ctx); ok && isAggregateType(typ) {
			// Inferred-aggregate case (v0.3 Phase 0 #4 unification): a
			// short_var whose RHS resolves to a struct/array by value —
			// e.g. `event := makeEvent()` returning *MyEvent or MyEvent,
			// or `arr := otherArr` aliasing a fixed-length array local.
			sites.StackLocals = append(sites.StackLocals, StackLocalSite{
				Function: fn,
				Stmt:     stmt,
				Type:     typ,
			})
			ctx.locals[stmt.Name] = typ
		} else if typ, ok := inferStackLocalType(stmt.Value, ctx); ok {
			// Track non-aggregate locals so subsequent inference can
			// resolve `x := y` chains.
			ctx.locals[stmt.Name] = typ
		}

	case "var_decl":
		if isAggregateType(stmt.Type) {
			sites.StackLocals = append(sites.StackLocals, StackLocalSite{
				Function: fn,
				Stmt:     stmt,
				Type:     stmt.Type,
			})
		}
		ctx.locals[stmt.Name] = stmt.Type

	case "assign":
		// `x = y` does not introduce a new local, but if the LHS is an
		// ident and we can infer the RHS type, refresh the entry so
		// downstream short_vars can resolve through reassigned locals.
		if stmt.Target != nil && stmt.Target.Kind == "ident" {
			if typ, ok := inferStackLocalType(stmt.Value, ctx); ok {
				ctx.locals[stmt.Target.Name] = typ
			}
		}
	}

	// Collect helper call sites from all expressions within this statement.
	collectHelperCallExprs(fn, stmt, sites)

	// Recurse into Init and Post directly using the real pointer — covers both
	// for-loop init/post and if-init (C1 fix). Using the pointer avoids creating
	// a temporary copy slice that would break pointer identity (C2 fix).
	if stmt.Init != nil {
		collectStmt(fn, stmt.Init, ctx, sites)
	}
	if stmt.Post != nil {
		collectStmt(fn, stmt.Post, ctx, sites)
	}

	// Recurse into all nested statement bodies.
	if len(stmt.Then) > 0 {
		collectStmts(fn, stmt.Then, ctx, sites)
	}
	if len(stmt.Else) > 0 {
		collectStmts(fn, stmt.Else, ctx, sites)
	}
	if len(stmt.Body) > 0 {
		collectStmts(fn, stmt.Body, ctx, sites)
	}
	for ci := range stmt.Cases {
		collectStmts(fn, stmt.Cases[ci].Body, ctx, sites)
	}
}

// inferStackLocalType resolves the type of an expression for stack-local
// detection. It mirrors the subset of expression-type inference the legacy
// stack estimator performed in stack.go::exprType — enough to recognize the
// inferred-aggregate short_var shape (`event := someCall()`,
// `arr := otherArr`, `event := *somePtr`). Conservative: returns false when
// the type cannot be resolved without further information; the caller treats
// that as "no stack-local site recorded."
func inferStackLocalType(expr *ir.Expr, ctx *collectCtx) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	switch expr.Kind {
	case "ident":
		typ, ok := ctx.locals[expr.Name]
		return typ, ok
	case "struct_lit":
		return ir.Type{Name: expr.Name}, expr.Name != ""
	case "call":
		// ringbuf.reserve / map.lookup return pointers to the map value
		// type; those are handled in collectStmt's short_var arms so the
		// resource validators can claim them first. The inference here
		// covers the remaining call shapes — user-defined helpers
		// returning an aggregate by value or pointer.
		if mapName, ok := reserveCall(expr); ok {
			return ptrToType(ctx.mapValues[mapName]), true
		}
		if mapName, ok := mapLookupCall(expr); ok {
			return ptrToType(ctx.mapValues[mapName]), true
		}
		// Resolve user-helper calls via the function index. Compiler-known
		// `bpf.*` helpers are not in the index and fall through to false;
		// none of them return user-defined aggregates today.
		name := irQualifiedName(expr.Func)
		if fn, ok := ctx.funcs[name]; ok {
			return fn.Return, true
		}
		return ir.Type{}, false
	case "selector":
		operand, ok := inferStackLocalType(expr.Operand, ctx)
		if !ok {
			return ir.Type{}, false
		}
		if operand.Ptr && operand.Elem != nil {
			operand = *operand.Elem
		}
		decl, ok := ctx.structs[operand.Name]
		if !ok {
			return ir.Type{}, false
		}
		for _, field := range decl.Fields {
			if field.Name == expr.Field {
				return field.Type, true
			}
		}
		return ir.Type{}, false
	case "unary":
		operand, ok := inferStackLocalType(expr.Operand, ctx)
		if !ok {
			return ir.Type{}, false
		}
		if expr.Op == "&" {
			return ptrToType(operand), true
		}
		if expr.Op == "*" && operand.Ptr && operand.Elem != nil {
			return *operand.Elem, true
		}
		return operand, true
	}
	return ir.Type{}, false
}

// ptrToType builds a pointer Type wrapping elem. Mirrors the helper of the
// same shape in stack.go (kept package-local so both files can share it once
// stack.go is reworked to consume StackLocalSite.Type).
func ptrToType(elem ir.Type) ir.Type {
	e := elem
	return ir.Type{Name: elem.Name, Ptr: true, Elem: &e}
}

// userHelperReturningResource reports whether expr is a call to a user
// helper whose return type is a resource pointer (single-hop *NamedStruct).
// Returns (helperName, true) on match. Used by Collect to register
// RingbufHelperReturnSite entries — see Sites.RingbufHelperReturn.
//
// The verdict (ReturnsResource / Maybe / Alias / Unknown) is consulted at
// validateTypedRingbuf time via HelperEffects.ReturnEffectFor; Collect
// only filters by *return-type shape* because HelperEffects has not been
// built yet at collection time.
func userHelperReturningResource(expr *ir.Expr, ctx *collectCtx) (string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil {
		return "", false
	}
	if expr.Func.Kind != "ident" {
		return "", false
	}
	name := expr.Func.Name
	fn, ok := ctx.funcs[name]
	if !ok {
		return "", false
	}
	// Mirror the types-layer helperResourceReturnType predicate at the IR
	// level: single-hop pointer-to-named-struct, no nested pointers.
	t := fn.Return
	if !t.Ptr || t.Name == "" || t.Len != "" {
		return "", false
	}
	switch t.Name {
	case "bool", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64":
		return "", false
	}
	if t.Elem != nil && t.Elem.Ptr {
		return "", false
	}
	return name, true
}

// collectHelperCallExprs walks all expressions directly owned by stmt and
// appends HelperCallSite entries for each bpf.* call found. It does NOT
// recurse into stmt.Init or stmt.Post — collectStmt handles those via direct
// pointer recursion to avoid double-traversal and to preserve pointer identity.
func collectHelperCallExprs(fn *ir.Function, stmt *ir.Statement, sites *Sites) {
	collectHelperExpr(fn, stmt.Value, sites)
	collectHelperExpr(fn, stmt.Target, sites)
	collectHelperExpr(fn, stmt.Expr, sites)
	collectHelperExpr(fn, stmt.Cond, sites)
}

func collectHelperExpr(fn *ir.Function, expr *ir.Expr, sites *Sites) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		name := irQualifiedName(expr.Func)
		if len(name) > len("bpf.") && name[:len("bpf.")] == "bpf." {
			sites.HelperCall = append(sites.HelperCall, HelperCallSite{Function: fn, Expr: expr})
		}
	}
	collectHelperExpr(fn, expr.Operand, sites)
	collectHelperExpr(fn, expr.Left, sites)
	collectHelperExpr(fn, expr.Right, sites)
	collectHelperExpr(fn, expr.Func, sites)
	for i := range expr.Args {
		collectHelperExpr(fn, &expr.Args[i], sites)
	}
	for i := range expr.Fields {
		collectHelperExpr(fn, &expr.Fields[i].Value, sites)
	}
}

// isAggregateType reports whether typ is a struct (named, non-primitive type)
// or a fixed-length array. These are the types that occupy eBPF stack space.
func isAggregateType(typ ir.Type) bool {
	if typ.Ptr {
		return false
	}
	// Fixed-length array: Len is non-empty and Elem is set.
	if typ.Len != "" && typ.Elem != nil {
		return true
	}
	// Named struct type: non-empty name that is not a primitive scalar.
	if typ.Name != "" {
		switch typ.Name {
		case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool":
			return false
		default:
			return true
		}
	}
	return false
}
