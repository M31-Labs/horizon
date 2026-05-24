package validate

import (
	"fmt"
	"strconv"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

const maxBPFStackBytes = 512

func ValidateStack(program ir.Program) []diag.Diagnostic {
	structs := map[string]ir.Struct{}
	for _, decl := range program.Structs {
		structs[decl.Name] = decl
	}
	maps := map[string]ir.Map{}
	for _, m := range program.Maps {
		maps[m.Name] = m
	}

	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		if !hasTypedStatements(fn) {
			continue
		}
		usage := estimateStack(fn, structs, maps)
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
	structs map[string]ir.Struct
	maps    map[string]ir.Map
	locals  map[string]ir.Type
	usage   stackUsage
}

func estimateStack(fn ir.Function, structs map[string]ir.Struct, maps map[string]ir.Map) stackUsage {
	e := stackEstimator{
		structs: structs,
		maps:    maps,
		locals:  map[string]ir.Type{},
	}
	for _, param := range fn.Params {
		e.locals[param.Name] = param.Type
	}
	e.walkStatements(functionStatements(fn))
	return e.usage
}

func (e *stackEstimator) walkStatements(stmts []ir.Statement) {
	for _, stmt := range stmts {
		e.walkStatement(stmt)
	}
}

func (e *stackEstimator) walkStatement(stmt ir.Statement) {
	switch stmt.Kind {
	case "short_var":
		if stmt.Value != nil && stmt.Value.Kind == "struct_lit" {
			e.walkExprChildren(stmt.Value)
		} else {
			e.walkExpr(stmt.Value)
		}
		if typ, ok := e.exprType(stmt.Value); ok {
			e.locals[stmt.Name] = typ
			if bytes := e.aggregateSize(typ); bytes > 0 {
				e.usage.LocalBytes += bytes
				e.trackPrimary(stmt.Span, bytes)
			}
		}
	case "assign":
		e.walkExpr(stmt.Target)
		e.walkExpr(stmt.Value)
		if stmt.Target != nil && stmt.Target.Kind == "ident" {
			if typ, ok := e.exprType(stmt.Value); ok {
				e.locals[stmt.Target.Name] = typ
			}
		}
	case "expr":
		e.walkExpr(stmt.Expr)
	case "return":
		e.walkExpr(stmt.Value)
	case "if":
		e.walkExpr(stmt.Cond)
		e.walkStatements(stmt.Then)
		e.walkStatements(stmt.Else)
	case "for":
		if stmt.Init != nil {
			e.walkStatement(*stmt.Init)
		}
		e.walkExpr(stmt.Cond)
		if stmt.Post != nil {
			e.walkStatement(*stmt.Post)
		}
		e.walkStatements(stmt.Body)
	}
}

func (e *stackEstimator) walkExpr(expr *ir.Expr) {
	if expr == nil {
		return
	}
	if expr.Kind == "struct_lit" {
		bytes := e.aggregateSize(ir.Type{Name: expr.Name})
		if bytes > e.usage.MaxTemp {
			e.usage.MaxTemp = bytes
			e.trackPrimary(expr.Span, bytes)
		}
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

func (e *stackEstimator) trackPrimary(primary span.Span, bytes int) {
	if bytes <= 0 || primary.IsZero() {
		return
	}
	if e.usage.Primary.IsZero() || bytes >= e.usage.total() {
		e.usage.Primary = primary
	}
}

func (e *stackEstimator) exprType(expr *ir.Expr) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	switch expr.Kind {
	case "ident":
		typ, ok := e.locals[expr.Name]
		return typ, ok
	case "int":
		return ir.Type{Name: "i64"}, true
	case "struct_lit":
		return ir.Type{Name: expr.Name}, expr.Name != ""
	case "call":
		if mapName, ok := reserveCall(expr); ok {
			return ptrToStackType(e.mapValue(mapName)), true
		}
		if mapName, ok := mapLookupCall(expr); ok {
			return ptrToStackType(e.mapValue(mapName)), true
		}
		return ir.Type{Name: "i64"}, true
	case "selector":
		operand, ok := e.exprType(expr.Operand)
		if !ok {
			return ir.Type{}, false
		}
		if operand.Ptr && operand.Elem != nil {
			operand = *operand.Elem
		}
		decl, ok := e.structs[operand.Name]
		if !ok {
			return ir.Type{}, false
		}
		for _, field := range decl.Fields {
			if field.Name == expr.Field {
				return field.Type, true
			}
		}
	case "unary":
		operand, ok := e.exprType(expr.Operand)
		if !ok {
			return ir.Type{}, false
		}
		if expr.Op == "&" {
			return ptrToStackType(operand), true
		}
		return operand, true
	case "binary":
		left, ok := e.exprType(expr.Left)
		if ok {
			return left, true
		}
		return ir.Type{Name: "i64"}, true
	}
	return ir.Type{}, false
}

func (e *stackEstimator) mapValue(name string) ir.Type {
	if m, ok := e.maps[name]; ok {
		return m.Val
	}
	return ir.Type{}
}

func ptrToStackType(typ ir.Type) ir.Type {
	elem := typ
	return ir.Type{Name: typ.Name, Ptr: true, Elem: &elem}
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
