package validate

import "m31labs.dev/horizon/ir"

// Sites holds all typed IR sites of interest collected by a single pass over
// an ir.Program. Task 3b will migrate per-validator walks to consume this
// instead of each re-walking the tree independently.
type Sites struct {
	Loops          []LoopSite
	RingbufReserve []RingbufReserveSite
	MapLookup      []MapLookupSite
	HelperCall     []HelperCallSite
	PacketHeader   []PacketHeaderSite
	StackLocals    []StackLocalSite
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

// StackLocalSite is a var_decl whose declared type is an aggregate (struct or
// fixed-length array), or a short_var whose value is a struct literal. These
// are the sites that consume eBPF stack space.
type StackLocalSite struct {
	Function *ir.Function
	Stmt     *ir.Statement
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

	var sites Sites
	for i := range program.Functions {
		fn := &program.Functions[i]
		if !hasTypedStatements(*fn) {
			continue
		}
		for j := range fn.Body {
			collectStmts(fn, fn.Body[j].Statements, ringMaps, lookupMaps, &sites)
		}
	}
	return sites
}

func collectStmts(fn *ir.Function, stmts []ir.Statement, ringMaps map[string]bool, lookupMaps map[string]bool, sites *Sites) {
	for i := range stmts {
		stmt := &stmts[i]
		switch stmt.Kind {
		case "for":
			sites.Loops = append(sites.Loops, LoopSite{Function: fn, Stmt: stmt})

		case "short_var":
			if mapName, ok := reserveCall(stmt.Value); ok && ringMaps[mapName] {
				sites.RingbufReserve = append(sites.RingbufReserve, RingbufReserveSite{
					Function: fn,
					Stmt:     stmt,
					MapName:  mapName,
				})
			} else if mapName, ok := mapLookupCall(stmt.Value); ok && lookupMaps[mapName] {
				sites.MapLookup = append(sites.MapLookup, MapLookupSite{
					Function: fn,
					Stmt:     stmt,
					MapName:  mapName,
				})
			} else if helper, ok := xdpPacketHeaderCall(stmt.Value); ok {
				sites.PacketHeader = append(sites.PacketHeader, PacketHeaderSite{
					Function: fn,
					Stmt:     stmt,
					Helper:   helper,
				})
			} else if stmt.Value != nil && stmt.Value.Kind == "struct_lit" {
				sites.StackLocals = append(sites.StackLocals, StackLocalSite{
					Function: fn,
					Stmt:     stmt,
				})
			}

		case "var_decl":
			if isAggregateType(stmt.Type) {
				sites.StackLocals = append(sites.StackLocals, StackLocalSite{
					Function: fn,
					Stmt:     stmt,
				})
			}
		}

		// Collect helper call sites from all expressions within this statement.
		collectHelperCallExprs(fn, stmt, sites)

		// Recurse into all nested statement bodies.
		if len(stmt.Then) > 0 {
			collectStmts(fn, stmt.Then, ringMaps, lookupMaps, sites)
		}
		if len(stmt.Else) > 0 {
			collectStmts(fn, stmt.Else, ringMaps, lookupMaps, sites)
		}
		if len(stmt.Body) > 0 {
			collectStmts(fn, stmt.Body, ringMaps, lookupMaps, sites)
		}
		for _, c := range stmt.Cases {
			collectStmts(fn, c.Body, ringMaps, lookupMaps, sites)
		}
		// Recurse into for-loop init and post (single-statement sub-trees).
		if stmt.Kind == "for" {
			if stmt.Init != nil {
				collectStmts(fn, []ir.Statement{*stmt.Init}, ringMaps, lookupMaps, sites)
			}
			if stmt.Post != nil {
				collectStmts(fn, []ir.Statement{*stmt.Post}, ringMaps, lookupMaps, sites)
			}
		}
	}
}

// collectHelperCallExprs walks all expressions reachable from stmt and appends
// HelperCallSite entries for each bpf.* call found.
func collectHelperCallExprs(fn *ir.Function, stmt *ir.Statement, sites *Sites) {
	collectHelperExpr(fn, stmt.Value, sites)
	collectHelperExpr(fn, stmt.Target, sites)
	collectHelperExpr(fn, stmt.Expr, sites)
	collectHelperExpr(fn, stmt.Cond, sites)
	if stmt.Init != nil {
		collectHelperCallExprs(fn, stmt.Init, sites)
	}
	if stmt.Post != nil {
		collectHelperCallExprs(fn, stmt.Post, sites)
	}
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
