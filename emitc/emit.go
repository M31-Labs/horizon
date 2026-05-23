package emitc

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func Emit(program ir.Program) (Output, error) {
	var b strings.Builder
	b.WriteString("#include \"vmlinux.h\"\n")
	b.WriteString("#include <bpf/bpf_helpers.h>\n\n")
	b.WriteString("#include <bpf/bpf_tracing.h>\n\n")
	b.WriteString("char LICENSE[] SEC(\"license\") = \"GPL\";\n")
	emitHelperWrappers(&b)
	for _, decl := range program.Structs {
		emitStruct(&b, decl)
	}
	for _, m := range program.Maps {
		emitMap(&b, m)
	}
	for _, m := range program.Maps {
		emitMapWrappers(&b, m)
	}
	sourceMap := ir.SourceMap{
		Schema:    "m31labs.dev/horizon/sourcemap/v0",
		Generated: ir.GeneratedSource{Language: "c"},
	}
	for _, fn := range program.Functions {
		env := newCEnv(program)
		startLine := strings.Count(b.String(), "\n") + 1
		fmt.Fprintf(&b, "\nSEC(%q)\nint %s(%s) {\n", fn.Section.Name, fn.Name, cContext(fn))
		for _, stmt := range functionStatements(fn) {
			emitStatement(&b, stmt, program, 1, &sourceMap, fn, env)
		}
		b.WriteString("}\n")
		sourceMap.Mappings = append(sourceMap.Mappings, ir.SourceMapping{
			Source:   fn.Span,
			Function: fn.Name,
			Section:  fn.Section.Name,
			Node:     "function",
			Generated: span.Span{
				Start: span.Point{Line: startLine, Column: 1},
				End:   span.Point{Line: strings.Count(b.String(), "\n") + 1, Column: 1},
			},
		})
	}
	sourceMap.Sources = sourceMapSources(sourceMap.Mappings)
	return Output{Code: b.String(), SourceMap: sourceMap}, nil
}

type cEnv struct {
	ptrLocals map[string]bool
	locals    map[string]ir.Type
	structs   map[string]ir.Struct
	maps      map[string]ir.Map
}

func newCEnv(program ir.Program) *cEnv {
	env := &cEnv{
		ptrLocals: map[string]bool{},
		locals:    map[string]ir.Type{},
		structs:   map[string]ir.Struct{},
		maps:      map[string]ir.Map{},
	}
	for _, decl := range program.Structs {
		env.structs[decl.Name] = decl
	}
	for _, m := range program.Maps {
		env.maps[m.Name] = m
	}
	return env
}

func (e *cEnv) setLocal(name string, typ ir.Type) {
	if e == nil || name == "" {
		return
	}
	e.locals[name] = typ
	e.ptrLocals[name] = typ.Ptr
}

func (e *cEnv) isPtr(name string) bool {
	if e == nil {
		return false
	}
	return e.ptrLocals[name]
}

func (e *cEnv) local(name string) (ir.Type, bool) {
	if e == nil {
		return ir.Type{}, false
	}
	typ, ok := e.locals[name]
	return typ, ok
}

func emitHelperWrappers(b *strings.Builder) {
	b.WriteString(`
static __always_inline __u32 hzn_current_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 hzn_current_ppid(void) {
    return 0;
}

static __always_inline __u32 hzn_current_uid(void) {
    return (__u32)bpf_get_current_uid_gid();
}

static __always_inline long hzn_current_comm(void *dst, __u32 size) {
    return bpf_get_current_comm(dst, size);
}
`)
}

func emitStruct(b *strings.Builder, decl ir.Struct) {
	fmt.Fprintf(b, "\nstruct %s {\n", decl.Name)
	for _, field := range decl.Fields {
		if field.Type.Len != "" && field.Type.Elem != nil {
			fmt.Fprintf(b, "    %s %s[%s];\n", cType(*field.Type.Elem), field.Name, field.Type.Len)
			continue
		}
		fmt.Fprintf(b, "    %s %s;\n", cType(field.Type), field.Name)
	}
	b.WriteString("};\n")
}

func emitMap(b *strings.Builder, m ir.Map) {
	switch m.Kind {
	case ir.MapKindRingbuf:
		fmt.Fprintf(b, `
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} %s SEC(".maps");
`, m.Name)
	case ir.MapKindHash, ir.MapKindArray:
		mapType := "BPF_MAP_TYPE_HASH"
		if m.Kind == ir.MapKindArray {
			mapType = "BPF_MAP_TYPE_ARRAY"
		}
		fmt.Fprintf(b, `
struct {
    __uint(type, %s);
    __uint(max_entries, 1024);
    __type(key, %s);
    __type(value, %s);
} %s SEC(".maps");
`, mapType, cType(m.Key), cType(m.Val), m.Name)
	}
}

func emitMapWrappers(b *strings.Builder, m ir.Map) {
	switch m.Kind {
	case ir.MapKindRingbuf:
		emitRingbufWrappers(b, m)
	case ir.MapKindHash, ir.MapKindArray:
		emitLookupMapWrappers(b, m)
	}
}

func emitRingbufWrappers(b *strings.Builder, m ir.Map) {
	if m.Val.Name == "" {
		return
	}
	typ := "struct " + m.Val.Name
	fmt.Fprintf(b, `
static __always_inline %s *%s_reserve(void) {
    return bpf_ringbuf_reserve(&%s, sizeof(%s), 0);
}

static __always_inline void %s_submit(%s *value) {
    bpf_ringbuf_submit(value, 0);
}

static __always_inline void %s_discard(%s *value) {
    bpf_ringbuf_discard(value, 0);
}
`, typ, m.Name, m.Name, typ, m.Name, typ, m.Name, typ)
}

func emitLookupMapWrappers(b *strings.Builder, m ir.Map) {
	if m.Key.Name == "" || m.Val.Name == "" {
		return
	}
	keyType := cType(m.Key)
	valueType := cType(m.Val)
	fmt.Fprintf(b, `
static __always_inline %s *%s_lookup(%s key) {
    return bpf_map_lookup_elem(&%s, &key);
}

static __always_inline long %s_update(%s key, %s value) {
    return bpf_map_update_elem(&%s, &key, &value, BPF_ANY);
}
`, valueType, m.Name, keyType, m.Name, m.Name, keyType, valueType, m.Name)
	if m.Kind == ir.MapKindHash {
		fmt.Fprintf(b, `
static __always_inline long %s_delete(%s key) {
    return bpf_map_delete_elem(&%s, &key);
}
`, m.Name, keyType, m.Name)
	}
}

func cType(t ir.Type) string {
	if t.Ptr && t.Elem != nil {
		return cType(*t.Elem) + " *"
	}
	switch t.Name {
	case "u8":
		return "__u8"
	case "u16":
		return "__u16"
	case "u32":
		return "__u32"
	case "u64":
		return "__u64"
	case "i8":
		return "__s8"
	case "i16":
		return "__s16"
	case "i32":
		return "__s32"
	case "i64":
		return "__s64"
	case "bool":
		return "bool"
	default:
		if t.Name != "" {
			return "struct " + t.Name
		}
		return "void"
	}
}

func cContext(fn ir.Function) string {
	if fn.Section.Kind != ir.ProgramTracepoint || fn.Section.Attach == "" {
		return "void *ctx"
	}
	event := fn.Section.Attach
	if idx := strings.IndexByte(event, ':'); idx >= 0 {
		event = event[idx+1:]
	}
	return "struct trace_event_raw_" + cIdent(event) + " *ctx"
}

func cIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func emitStatement(b *strings.Builder, stmt ir.Statement, program ir.Program, depth int, sourceMap *ir.SourceMap, fn ir.Function, env *cEnv) {
	startLine := strings.Count(b.String(), "\n") + 1
	indent := strings.Repeat("    ", depth)
	switch stmt.Kind {
	case "short_var":
		if mapName, ok := reserveCall(stmt.Value); ok {
			fmt.Fprintf(b, "%s%s *%s = %s_reserve();\n", indent, reserveType(mapName, program.Maps), stmt.Name, mapName)
			env.setLocal(stmt.Name, ptrToMapValue(mapName, env))
		} else if mapName, ok := lookupCall(stmt.Value); ok {
			fmt.Fprintf(b, "%s%s *%s = %s;\n", indent, mapValueType(mapName, program.Maps), stmt.Name, cExpr(stmt.Value, env))
			env.setLocal(stmt.Name, ptrToMapValue(mapName, env))
		} else {
			typ := inferredExprType(stmt.Value, env)
			fmt.Fprintf(b, "%s%s %s = %s;\n", indent, cType(typ), stmt.Name, cExpr(stmt.Value, env))
			env.setLocal(stmt.Name, typ)
		}
	case "assign":
		fmt.Fprintf(b, "%s%s = %s;\n", indent, cExpr(stmt.Target, env), cExpr(stmt.Value, env))
		if stmt.Target != nil && stmt.Target.Kind == "ident" {
			env.setLocal(stmt.Target.Name, inferredExprType(stmt.Value, env))
		}
	case "expr":
		if mapName, op, varName, ok := consumeCall(stmt.Expr); ok {
			fmt.Fprintf(b, "%s%s_%s(%s);\n", indent, mapName, op, varName)
		} else {
			fmt.Fprintf(b, "%s%s;\n", indent, cExpr(stmt.Expr, env))
		}
	case "return":
		fmt.Fprintf(b, "%sreturn %s;\n", indent, cExpr(stmt.Value, env))
	case "if":
		fmt.Fprintf(b, "%sif (%s) {\n", indent, cExpr(stmt.Cond, env))
		for _, child := range stmt.Then {
			emitStatement(b, child, program, depth+1, sourceMap, fn, env)
		}
		fmt.Fprintf(b, "%s}\n", indent)
	case "for":
		if stmt.Init != nil || stmt.Post != nil {
			fmt.Fprintf(b, "%sfor (%s; %s; %s) {\n", indent, cForInit(stmt.Init, program, env), cExpr(stmt.Cond, env), cForPost(stmt.Post))
		} else if stmt.Cond == nil || stmt.Cond.Kind == "" {
			fmt.Fprintf(b, "%sfor (;;) {\n", indent)
		} else {
			fmt.Fprintf(b, "%sfor (; %s; ) {\n", indent, cExpr(stmt.Cond, env))
		}
		for _, child := range stmt.Body {
			emitStatement(b, child, program, depth+1, sourceMap, fn, env)
		}
		fmt.Fprintf(b, "%s}\n", indent)
	case "inc":
		fmt.Fprintf(b, "%s%s%s;\n", indent, stmt.Name, stmt.Op)
	case "raw":
		if stmt.Value != nil {
			fmt.Fprintf(b, "%s%s;\n", indent, stmt.Value.Value)
		}
	default:
		fmt.Fprintf(b, "%s/* unsupported Horizon statement */\n", indent)
	}
	if sourceMap != nil && !stmt.Span.IsZero() {
		sourceMap.Mappings = append(sourceMap.Mappings, ir.SourceMapping{
			Source:   stmt.Span,
			Function: fn.Name,
			Section:  fn.Section.Name,
			Node:     stmt.Kind,
			Generated: span.Span{
				Start: span.Point{Line: startLine, Column: 1},
				End:   span.Point{Line: strings.Count(b.String(), "\n") + 1, Column: 1},
			},
		})
	}
}

func reserveType(mapName string, maps []ir.Map) string {
	for _, m := range maps {
		if m.Name == mapName && m.Val.Name != "" {
			return "struct " + m.Val.Name
		}
	}
	return "void"
}

func cForInit(stmt *ir.Statement, program ir.Program, env *cEnv) string {
	if stmt == nil {
		return ""
	}
	switch stmt.Kind {
	case "short_var":
		typ := inferredExprType(stmt.Value, env)
		env.setLocal(stmt.Name, typ)
		return fmt.Sprintf("%s %s = %s", cType(typ), stmt.Name, cExpr(stmt.Value, env))
	case "assign":
		return fmt.Sprintf("%s = %s", cExpr(stmt.Target, env), cExpr(stmt.Value, env))
	default:
		return ""
	}
}

func cForPost(stmt *ir.Statement) string {
	if stmt == nil {
		return ""
	}
	switch stmt.Kind {
	case "inc":
		return stmt.Name + stmt.Op
	default:
		return ""
	}
}

func inferredExprType(expr *ir.Expr, env *cEnv) ir.Type {
	if typ, ok := cExprType(expr, env); ok {
		return typ
	}
	return ir.Type{Name: "i64"}
}

func cExprType(expr *ir.Expr, env *cEnv) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	switch expr.Kind {
	case "ident":
		return env.local(expr.Name)
	case "int":
		return ir.Type{Name: "i64"}, true
	case "nil":
		return ptrTo(ir.Type{}), true
	case "binary":
		return ir.Type{Name: "bool"}, true
	case "struct_lit":
		if expr.Name == "" {
			return ir.Type{}, false
		}
		return ir.Type{Name: expr.Name}, true
	case "call":
		if name := qualifiedName(expr.Func); name != "" {
			switch name {
			case "bpf.current_pid", "bpf.current_ppid", "bpf.current_uid":
				return ir.Type{Name: "u32"}, true
			case "bpf.current_comm":
				return ir.Type{Name: "i64"}, true
			}
		}
		if mapName, ok := reserveCall(expr); ok {
			return ptrToMapValue(mapName, env), true
		}
		if mapName, ok := lookupCall(expr); ok {
			return ptrToMapValue(mapName, env), true
		}
	case "selector":
		return selectorExprType(expr, env)
	case "unary":
		switch expr.Op {
		case "&":
			operand, ok := cExprType(expr.Operand, env)
			if !ok {
				return ir.Type{}, false
			}
			return ptrTo(operand), true
		case "*":
			operand, ok := cExprType(expr.Operand, env)
			if !ok || !operand.Ptr || operand.Elem == nil {
				return ir.Type{}, false
			}
			return *operand.Elem, true
		}
	}
	return ir.Type{}, false
}

func selectorExprType(expr *ir.Expr, env *cEnv) (ir.Type, bool) {
	if expr == nil || expr.Operand == nil {
		return ir.Type{}, false
	}
	operand, ok := cExprType(expr.Operand, env)
	if !ok {
		return ir.Type{}, false
	}
	if operand.Ptr && operand.Elem != nil {
		operand = *operand.Elem
	}
	structDecl, ok := env.structs[operand.Name]
	if !ok {
		return ir.Type{}, false
	}
	for _, field := range structDecl.Fields {
		if field.Name == expr.Field {
			return field.Type, true
		}
	}
	return ir.Type{}, false
}

func ptrToMapValue(mapName string, env *cEnv) ir.Type {
	if env != nil {
		if m, ok := env.maps[mapName]; ok {
			return ptrTo(m.Val)
		}
	}
	return ptrTo(ir.Type{})
}

func ptrTo(typ ir.Type) ir.Type {
	elem := typ
	return ir.Type{Name: typ.Name, Ptr: true, Elem: &elem}
}

func cExpr(expr *ir.Expr, env *cEnv) string {
	if expr == nil {
		return "0"
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "int":
		return expr.Value
	case "nil":
		return "0"
	case "selector":
		if expr.Operand == nil {
			return expr.Field
		}
		access := "."
		if cExprIsPointer(expr.Operand, env) {
			access = "->"
		}
		return cExpr(expr.Operand, env) + access + expr.Field
	case "unary":
		return expr.Op + cExpr(expr.Operand, env)
	case "binary":
		return cExpr(expr.Left, env) + " " + expr.Op + " " + cExpr(expr.Right, env)
	case "call":
		return cCallExpr(expr, env)
	case "struct_lit":
		return cStructLiteral(expr, env)
	case "raw":
		return expr.Value
	default:
		return "0"
	}
}

func cExprIsPointer(expr *ir.Expr, env *cEnv) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case "ident":
		return env.isPtr(expr.Name)
	case "nil":
		return true
	case "unary":
		return expr.Op == "&"
	case "call":
		if _, ok := reserveCall(expr); ok {
			return true
		}
		if _, ok := lookupCall(expr); ok {
			return true
		}
		return false
	default:
		return false
	}
}

func cStructLiteral(expr *ir.Expr, env *cEnv) string {
	if expr == nil || expr.Name == "" {
		return "(void){0}"
	}
	if len(expr.Fields) == 0 {
		return fmt.Sprintf("(%s){0}", cType(ir.Type{Name: expr.Name}))
	}
	fields := make([]string, 0, len(expr.Fields))
	for _, field := range expr.Fields {
		value := field.Value
		fields = append(fields, fmt.Sprintf(".%s = %s", field.Name, cExpr(&value, env)))
	}
	return fmt.Sprintf("(%s){ %s }", cType(ir.Type{Name: expr.Name}), strings.Join(fields, ", "))
}

func cCallExpr(expr *ir.Expr, env *cEnv) string {
	if expr == nil || expr.Kind != "call" {
		return "0"
	}
	if mapName, method, ok := mapMethodCall(expr); ok {
		args := make([]string, 0, len(expr.Args))
		for _, arg := range expr.Args {
			arg := arg
			args = append(args, cExpr(&arg, env))
		}
		return fmt.Sprintf("%s_%s(%s)", mapName, method, strings.Join(args, ", "))
	}
	if name := qualifiedName(expr.Func); name != "" {
		switch name {
		case "bpf.current_pid":
			return "hzn_current_pid()"
		case "bpf.current_ppid":
			return "hzn_current_ppid()"
		case "bpf.current_uid":
			return "hzn_current_uid()"
		case "bpf.current_comm":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("hzn_current_comm(%s, sizeof(%s))", cExpr(&arg, env), sizeofExpr(&arg, env))
			}
		}
	}
	args := make([]string, 0, len(expr.Args))
	for _, arg := range expr.Args {
		arg := arg
		args = append(args, cExpr(&arg, env))
	}
	return cExpr(expr.Func, env) + "(" + strings.Join(args, ", ") + ")"
}

func sizeofExpr(expr *ir.Expr, env *cEnv) string {
	if expr == nil {
		return "0"
	}
	if expr.Kind == "unary" && expr.Op == "&" && expr.Operand != nil {
		return cExpr(expr.Operand, env)
	}
	return cExpr(expr, env)
}

func qualifiedName(expr *ir.Expr) string {
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "selector":
		prefix := qualifiedName(expr.Operand)
		if prefix == "" {
			return expr.Field
		}
		return prefix + "." + expr.Field
	default:
		return ""
	}
}

func functionStatements(fn ir.Function) []ir.Statement {
	var out []ir.Statement
	for _, block := range fn.Body {
		out = append(out, block.Statements...)
	}
	return out
}

func reserveCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", false
	}
	if expr.Func.Field != "reserve" || expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" {
		return "", false
	}
	return expr.Func.Operand.Name, true
}

func lookupCall(expr *ir.Expr) (string, bool) {
	mapName, method, ok := mapMethodCall(expr)
	return mapName, ok && method == "lookup"
}

func mapMethodCall(expr *ir.Expr) (string, string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" {
		return "", "", false
	}
	switch expr.Func.Field {
	case "lookup", "update", "delete":
		return expr.Func.Operand.Name, expr.Func.Field, true
	default:
		return "", "", false
	}
}

func mapValueType(mapName string, maps []ir.Map) string {
	for _, m := range maps {
		if m.Name == mapName && m.Val.Name != "" {
			return cType(m.Val)
		}
	}
	return "void"
}

func consumeCall(expr *ir.Expr) (string, string, string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" || len(expr.Args) != 1 {
		return "", "", "", false
	}
	if expr.Func.Field != "submit" && expr.Func.Field != "discard" {
		return "", "", "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" || expr.Args[0].Kind != "ident" {
		return "", "", "", false
	}
	return expr.Func.Operand.Name, expr.Func.Field, expr.Args[0].Name, true
}

func sourceMapSources(mappings []ir.SourceMapping) []ir.Source {
	seen := map[string]int{}
	var sources []ir.Source
	for _, mapping := range mappings {
		path := string(mapping.Source.File)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = len(sources)
		sources = append(sources, ir.Source{ID: len(sources), Path: path})
	}
	return sources
}
