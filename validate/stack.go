package validate

import (
	"fmt"
	"strconv"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

const maxBPFStackBytes = 512

// AnalyzeStack runs stack-byte accounting per function.
//
// Site discovery is consumed from sites.StackLocals (v0.3 Phase 0 #4
// unification): each stack-local short_var / var_decl is indexed once during
// Collect, and AnalyzeStack reads the inferred Type from the site rather
// than re-running its own type-inference pass. The CFG-aware peak walker
// remains in this file because if/switch/for branch maxima are not encodable
// in a flat site list — sites tells us *which* statements own a stack-local
// and *what type* it is; the walker computes how those locals stack up
// across mutually-exclusive control-flow branches.
func AnalyzeStack(program ir.Program, sites Sites) []diag.Diagnostic {
	structs := map[string]ir.Struct{}
	for _, decl := range program.Structs {
		structs[decl.Name] = decl
	}

	// Index stack-local sites by their owning statement pointer so the
	// CFG walker can look up the inferred type for each declaration
	// without re-running expression-type inference.
	siteTypes := make(map[*ir.Statement]ir.Type, len(sites.StackLocals))
	for _, s := range sites.StackLocals {
		siteTypes[s.Stmt] = s.Type
	}

	var diags []diag.Diagnostic
	// Iterate by index so the statements walked here are the same
	// addressable storage that validate.Collect indexed in siteTypes.
	// Ranging by value would copy fn.Body and lose pointer identity
	// against the siteTypes map (which is keyed by *ir.Statement).
	for i := range program.Functions {
		fn := &program.Functions[i]
		if !hasTypedStatements(*fn) {
			continue
		}
		usage := estimateStack(fn, structs, siteTypes)
		if usage.total() <= maxBPFStackBytes {
			continue
		}
		primary := usage.Primary
		if primary.IsZero() {
			primary = fn.Span
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN2700",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q may use %d bytes of eBPF stack; the verifier limit is %d bytes", fn.Name, usage.total(), maxBPFStackBytes),
			Primary:  primary,
			Suggest:  "move large records into maps or ringbuf reservations instead of local structs or arrays",
		})
	}
	return diags
}

type stackUsage struct {
	LocalBytes int
	MaxTemp    int
	Primary    span.Span
}

func (u stackUsage) total() int {
	return u.LocalBytes + u.MaxTemp
}

type stackEstimator struct {
	structs    map[string]ir.Struct
	siteTypes  map[*ir.Statement]ir.Type
	localBytes int
	usage      stackUsage
}

func estimateStack(fn *ir.Function, structs map[string]ir.Struct, siteTypes map[*ir.Statement]ir.Type) stackUsage {
	e := stackEstimator{
		structs:   structs,
		siteTypes: siteTypes,
	}
	// Walk each block's Statements slice directly so the &stmts[i]
	// pointers match the ones validate.Collect indexed in siteTypes.
	for j := range fn.Body {
		e.walkStatements(fn.Body[j].Statements)
	}
	return e.usage
}

func (e *stackEstimator) walkStatements(stmts []ir.Statement) {
	for i := range stmts {
		e.walkStatement(&stmts[i])
	}
}

func (e *stackEstimator) walkStatement(stmt *ir.Statement) {
	switch stmt.Kind {
	case "short_var":
		if stmt.Value != nil && stmt.Value.Kind == "struct_lit" {
			e.walkExprChildren(stmt.Value)
		} else {
			e.walkExpr(stmt.Value)
		}
		// Site discovery is delegated to sites.StackLocals (populated by
		// validate.Collect): if this short_var was indexed there, charge
		// its inferred aggregate size against the running local total.
		if typ, ok := e.siteTypes[stmt]; ok {
			if bytes := e.aggregateSize(typ); bytes > 0 {
				e.localBytes += bytes
				e.trackPeak(e.localBytes, stmt.Span)
			}
		}
	case "var_decl":
		if stmt.Value != nil && stmt.Value.Kind == "struct_lit" {
			e.walkExprChildren(stmt.Value)
		} else {
			e.walkExpr(stmt.Value)
		}
		if bytes := e.aggregateSize(stmt.Type); bytes > 0 {
			e.localBytes += bytes
			e.trackPeak(e.localBytes, stmt.Span)
		}
	case "assign":
		e.walkExpr(stmt.Target)
		e.walkExpr(stmt.Value)
	case "expr":
		e.walkExpr(stmt.Expr)
	case "return":
		e.walkExpr(stmt.Value)
	case "if":
		ifEstimator := e.child()
		if stmt.Init != nil {
			ifEstimator.walkStatement(stmt.Init)
		}
		ifEstimator.walkExpr(stmt.Cond)
		thenEstimator := ifEstimator.child()
		thenEstimator.walkStatements(stmt.Then)
		e.mergePeak(thenEstimator.usage)
		if len(stmt.Else) > 0 {
			elseEstimator := ifEstimator.child()
			elseEstimator.walkStatements(stmt.Else)
			e.mergePeak(elseEstimator.usage)
		}
		e.mergePeak(ifEstimator.usage)
	case "switch":
		e.walkExpr(stmt.Value)
		for _, c := range stmt.Cases {
			for i := range c.Values {
				e.walkExpr(&c.Values[i])
			}
			caseEstimator := e.child()
			caseEstimator.walkStatements(c.Body)
			e.mergePeak(caseEstimator.usage)
		}
	case "for":
		loopEstimator := e.child()
		if stmt.Init != nil {
			loopEstimator.walkStatement(stmt.Init)
		}
		loopEstimator.walkExpr(stmt.Cond)
		if stmt.Post != nil {
			loopEstimator.walkStatement(stmt.Post)
		}
		bodyEstimator := loopEstimator.child()
		bodyEstimator.walkStatements(stmt.Body)
		loopEstimator.mergePeak(bodyEstimator.usage)
		e.mergePeak(loopEstimator.usage)
	}
}

func (e *stackEstimator) walkExpr(expr *ir.Expr) {
	if expr == nil {
		return
	}
	if expr.Kind == "struct_lit" {
		bytes := e.aggregateSize(ir.Type{Name: expr.Name})
		e.trackPeak(e.localBytes+bytes, expr.Span)
	}
	e.walkExprChildren(expr)
}

func (e *stackEstimator) walkExprChildren(expr *ir.Expr) {
	if expr == nil {
		return
	}
	e.walkExpr(expr.Operand)
	e.walkExpr(expr.Left)
	e.walkExpr(expr.Right)
	e.walkExpr(expr.Func)
	for i := range expr.Args {
		e.walkExpr(&expr.Args[i])
	}
	for i := range expr.Fields {
		e.walkExpr(&expr.Fields[i].Value)
	}
}

func (e *stackEstimator) child() stackEstimator {
	return stackEstimator{
		structs:    e.structs,
		siteTypes:  e.siteTypes,
		localBytes: e.localBytes,
		usage:      e.usage,
	}
}

func (e *stackEstimator) mergePeak(usage stackUsage) {
	if usage.total() > e.usage.total() {
		e.usage = usage
	}
}

func (e *stackEstimator) trackPeak(total int, primary span.Span) {
	if total <= e.usage.total() {
		return
	}
	e.usage.LocalBytes = total
	e.usage.MaxTemp = 0
	if !primary.IsZero() {
		e.usage.Primary = primary
	}
}

func (e *stackEstimator) aggregateSize(typ ir.Type) int {
	if typ.Ptr {
		return 0
	}
	if typ.Len != "" && typ.Elem != nil {
		n, err := strconv.ParseInt(typ.Len, 0, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return int(n) * e.typeSize(*typ.Elem)
	}
	if _, ok := e.structs[typ.Name]; ok {
		return e.typeSize(typ)
	}
	return 0
}

func (e *stackEstimator) typeSize(typ ir.Type) int {
	if typ.Ptr {
		return 8
	}
	if typ.Len != "" && typ.Elem != nil {
		n, err := strconv.ParseInt(typ.Len, 0, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return int(n) * e.typeSize(*typ.Elem)
	}
	switch typ.Name {
	case "u8", "i8", "bool":
		return 1
	case "u16", "i16":
		return 2
	case "u32", "i32":
		return 4
	case "u64", "i64":
		return 8
	}
	decl, ok := e.structs[typ.Name]
	if !ok {
		return 0
	}
	offset := 0
	maxAlign := 1
	for _, field := range decl.Fields {
		fieldSize := e.typeSize(field.Type)
		fieldAlign := typeAlign(field.Type)
		if fieldAlign > maxAlign {
			maxAlign = fieldAlign
		}
		offset = alignTo(offset, fieldAlign)
		offset += fieldSize
	}
	return alignTo(offset, maxAlign)
}

func typeAlign(typ ir.Type) int {
	if typ.Ptr {
		return 8
	}
	if typ.Len != "" && typ.Elem != nil {
		return typeAlign(*typ.Elem)
	}
	switch typ.Name {
	case "u8", "i8", "bool":
		return 1
	case "u16", "i16":
		return 2
	case "u32", "i32":
		return 4
	default:
		return 8
	}
}

func alignTo(value int, align int) int {
	if align <= 1 {
		return value
	}
	rem := value % align
	if rem == 0 {
		return value
	}
	return value + align - rem
}
