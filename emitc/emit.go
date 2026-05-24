package emitc

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func Emit(program ir.Program) (Output, error) {
	var b strings.Builder
	usage := analyzeUsage(program)
	b.WriteString("#include \"vmlinux.h\"\n")
	b.WriteString("#include <bpf/bpf_helpers.h>\n\n")
	b.WriteString("#include <bpf/bpf_tracing.h>\n\n")
	if usage.hasXDPPacketHelpers() {
		b.WriteString("#include <bpf/bpf_endian.h>\n\n")
	}
	if programHasXDP(program) {
		emitXDPActionFallbacks(&b)
	}
	b.WriteString("char LICENSE[] SEC(\"license\") = \"GPL\";\n")
	emitScalarABIAssertions(&b)
	emitHelperWrappers(&b, usage)
	if usage.hasXDPPacketHelpers() {
		emitXDPPacketHelpers(&b, usage)
	}
	for _, c := range program.Constants {
		emitConst(&b, c)
	}
	structs := ir.StructsByName(program.Structs)
	for _, decl := range program.Structs {
		emitStruct(&b, decl, structs)
	}
	for _, m := range program.Maps {
		emitMap(&b, m)
	}
	for _, m := range program.Maps {
		emitMapWrappers(&b, m, usage.mapMethods[m.Name])
	}
	sourceMap := ir.SourceMap{
		Schema:    "m31labs.dev/horizon/sourcemap/v0",
		Generated: ir.GeneratedSource{Language: "c"},
	}
	for _, fn := range program.Functions {
		env := newCEnv(program)
		startLine := strings.Count(b.String(), "\n") + 1
		fmt.Fprintf(&b, "\nSEC(%q)\nint %s(%s) {\n", fn.Section.Name, fn.Name, cContext(fn))
		b.WriteString("    (void)ctx;\n")
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
	constants map[string]bool
	structs   map[string]ir.Struct
	maps      map[string]ir.Map
}

func newCEnv(program ir.Program) *cEnv {
	env := &cEnv{
		ptrLocals: map[string]bool{},
		locals:    map[string]ir.Type{},
		constants: map[string]bool{},
		structs:   map[string]ir.Struct{},
		maps:      map[string]ir.Map{},
	}
	for _, decl := range program.Constants {
		env.constants[decl.Name] = true
	}
	for _, decl := range program.Structs {
		env.structs[decl.Name] = decl
	}
	for _, decl := range xdpPacketStructs() {
		env.structs[decl.Name] = decl
	}
	for _, m := range program.Maps {
		env.maps[m.Name] = m
	}
	return env
}

func xdpPacketStructs() []ir.Struct {
	return []ir.Struct{
		{
			Name: "xdp.Eth",
			Fields: []ir.Field{
				{Name: "dst", Type: fixedArrayType("u8", "6")},
				{Name: "src", Type: fixedArrayType("u8", "6")},
				{Name: "proto", Type: ir.Type{Name: "u16"}},
			},
		},
		{
			Name: "xdp.IPv4",
			Fields: []ir.Field{
				{Name: "version_ihl", Type: ir.Type{Name: "u8"}},
				{Name: "tos", Type: ir.Type{Name: "u8"}},
				{Name: "total_len", Type: ir.Type{Name: "u16"}},
				{Name: "id", Type: ir.Type{Name: "u16"}},
				{Name: "frag_off", Type: ir.Type{Name: "u16"}},
				{Name: "ttl", Type: ir.Type{Name: "u8"}},
				{Name: "protocol", Type: ir.Type{Name: "u8"}},
				{Name: "check", Type: ir.Type{Name: "u16"}},
				{Name: "src", Type: ir.Type{Name: "u32"}},
				{Name: "dst", Type: ir.Type{Name: "u32"}},
			},
		},
		{
			Name: "xdp.TCP",
			Fields: []ir.Field{
				{Name: "src_port", Type: ir.Type{Name: "u16"}},
				{Name: "dst_port", Type: ir.Type{Name: "u16"}},
				{Name: "seq", Type: ir.Type{Name: "u32"}},
				{Name: "ack", Type: ir.Type{Name: "u32"}},
				{Name: "data_off", Type: ir.Type{Name: "u8"}},
				{Name: "flags", Type: ir.Type{Name: "u8"}},
				{Name: "window", Type: ir.Type{Name: "u16"}},
				{Name: "check", Type: ir.Type{Name: "u16"}},
				{Name: "urg_ptr", Type: ir.Type{Name: "u16"}},
			},
		},
		{
			Name: "xdp.UDP",
			Fields: []ir.Field{
				{Name: "src_port", Type: ir.Type{Name: "u16"}},
				{Name: "dst_port", Type: ir.Type{Name: "u16"}},
				{Name: "len", Type: ir.Type{Name: "u16"}},
				{Name: "check", Type: ir.Type{Name: "u16"}},
			},
		},
	}
}

func fixedArrayType(elem string, len string) ir.Type {
	return ir.Type{Len: len, Elem: &ir.Type{Name: elem}}
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

type cUsage struct {
	helpers    map[string]bool
	mapMethods map[string]map[string]bool
	xdpHelpers map[string]bool
	maps       map[string]ir.Map
}

func analyzeUsage(program ir.Program) cUsage {
	usage := cUsage{
		helpers:    map[string]bool{},
		mapMethods: map[string]map[string]bool{},
		xdpHelpers: map[string]bool{},
		maps:       map[string]ir.Map{},
	}
	for _, m := range program.Maps {
		usage.maps[m.Name] = m
	}
	for _, fn := range program.Functions {
		for _, stmt := range functionStatements(fn) {
			usage.walkStatement(stmt)
		}
	}
	usage.expandXDPPacketDependencies()
	return usage
}

func (u *cUsage) walkStatement(stmt ir.Statement) {
	switch stmt.Kind {
	case "short_var":
		u.walkExpr(stmt.Value)
	case "assign":
		u.walkExpr(stmt.Target)
		u.walkExpr(stmt.Value)
	case "expr":
		u.walkExpr(stmt.Expr)
	case "return":
		u.walkExpr(stmt.Value)
	case "if":
		u.walkExpr(stmt.Cond)
		u.walkStatements(stmt.Then)
		u.walkStatements(stmt.Else)
	case "for":
		if stmt.Init != nil {
			u.walkStatement(*stmt.Init)
		}
		u.walkExpr(stmt.Cond)
		if stmt.Post != nil {
			u.walkStatement(*stmt.Post)
		}
		u.walkStatements(stmt.Body)
	case "raw":
		u.walkExpr(stmt.Value)
	}
}

func (u *cUsage) walkStatements(stmts []ir.Statement) {
	for _, stmt := range stmts {
		u.walkStatement(stmt)
	}
}

func (u *cUsage) walkExpr(expr *ir.Expr) {
	if expr == nil {
		return
	}
	if helper, ok := helperWrapperCall(expr); ok {
		u.helpers[helper] = true
	}
	if mapName, method, ok := wrapperMethodCall(expr); ok {
		u.addMapMethod(mapName, method)
	}
	if helper, ok := xdpPacketCall(expr); ok {
		u.xdpHelpers[helper] = true
	}
	u.walkExpr(expr.Operand)
	u.walkExpr(expr.Left)
	u.walkExpr(expr.Right)
	u.walkExpr(expr.Func)
	for i := range expr.Args {
		u.walkExpr(&expr.Args[i])
	}
	for i := range expr.Fields {
		u.walkExpr(&expr.Fields[i].Value)
	}
}

func (u *cUsage) addMapMethod(mapName string, method string) {
	if _, ok := u.maps[mapName]; !ok {
		return
	}
	if u.mapMethods[mapName] == nil {
		u.mapMethods[mapName] = map[string]bool{}
	}
	u.mapMethods[mapName][method] = true
}

func (u cUsage) hasXDPPacketHelpers() bool {
	return len(u.xdpHelpers) > 0
}

func (u *cUsage) expandXDPPacketDependencies() {
	if u.xdpHelpers["udp"] || u.xdpHelpers["tcp"] {
		u.xdpHelpers["l4_offset"] = true
		u.xdpHelpers["ipv4"] = true
		u.xdpHelpers["eth"] = true
	}
	if u.xdpHelpers["ipv4"] {
		u.xdpHelpers["eth"] = true
	}
}

func emitHelperWrappers(b *strings.Builder, usage cUsage) {
	if usage.helpers["current_pid"] {
		b.WriteString(`
static __always_inline __u32 hzn_current_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}
`)
	}

	if usage.helpers["current_ppid"] {
		b.WriteString(`
static __always_inline __u32 hzn_current_ppid(void) {
    return 0;
}
`)
	}

	if usage.helpers["current_uid"] {
		b.WriteString(`
static __always_inline __u32 hzn_current_uid(void) {
    return (__u32)bpf_get_current_uid_gid();
}
`)
	}

	if usage.helpers["current_comm"] {
		b.WriteString(`
static __always_inline long hzn_current_comm(void *dst, __u32 size) {
    return bpf_get_current_comm(dst, size);
}
`)
	}
}

func emitXDPActionFallbacks(b *strings.Builder) {
	b.WriteString(`#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4
#endif

`)
}

func programHasXDP(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramXDP {
			return true
		}
	}
	return false
}

func emitXDPPacketHelpers(b *strings.Builder, usage cUsage) {
	b.WriteString(`
struct hzn_xdp_eth {
    __u8 dst[6];
    __u8 src[6];
    __u16 proto;
} __attribute__((packed));

struct hzn_xdp_ipv4 {
    __u8 version_ihl;
    __u8 tos;
    __u16 total_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 src;
    __u32 dst;
} __attribute__((packed));

struct hzn_xdp_tcp {
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
    __u32 ack;
    __u8 data_off;
    __u8 flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

struct hzn_xdp_udp {
    __u16 src_port;
    __u16 dst_port;
    __u16 len;
    __u16 check;
} __attribute__((packed));
`)

	if usage.xdpHelpers["eth"] {
		b.WriteString(`
static __always_inline struct hzn_xdp_eth *hzn_xdp_eth(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct hzn_xdp_eth) > data_end) {
        return 0;
    }
    return data;
}
`)
	}

	if usage.xdpHelpers["ipv4"] {
		b.WriteString(`
static __always_inline struct hzn_xdp_ipv4 *hzn_xdp_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct hzn_xdp_eth *eth = hzn_xdp_eth(ctx);

    if (!eth || eth->proto != bpf_htons(0x0800)) {
        return 0;
    }

    void *ip = data + sizeof(struct hzn_xdp_eth);
    if (ip + sizeof(struct hzn_xdp_ipv4) > data_end) {
        return 0;
    }
    return ip;
}
`)
	}

	if usage.xdpHelpers["l4_offset"] {
		b.WriteString(`
static __always_inline __u64 hzn_xdp_l4_offset(struct xdp_md *ctx, __u8 protocol) {
    struct hzn_xdp_ipv4 *ip = hzn_xdp_ipv4(ctx);

    if (!ip || ip->protocol != protocol) {
        return 0;
    }

    __u8 ihl = ip->version_ihl & 0x0f;
    if (ihl < 5) {
        return 0;
    }
    return sizeof(struct hzn_xdp_eth) + ((__u64)ihl * 4);
}
`)
	}

	if usage.xdpHelpers["tcp"] {
		b.WriteString(`
static __always_inline struct hzn_xdp_tcp *hzn_xdp_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 off = hzn_xdp_l4_offset(ctx, 6);

    if (!off || data + off + sizeof(struct hzn_xdp_tcp) > data_end) {
        return 0;
    }
    return data + off;
}
`)
	}

	if usage.xdpHelpers["udp"] {
		b.WriteString(`
static __always_inline struct hzn_xdp_udp *hzn_xdp_udp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 off = hzn_xdp_l4_offset(ctx, 17);

    if (!off || data + off + sizeof(struct hzn_xdp_udp) > data_end) {
        return 0;
    }
    return data + off;
}
`)
	}
}

func emitConst(b *strings.Builder, c ir.Const) {
	if c.Name == "" {
		return
	}
	fmt.Fprintf(b, "\nstatic const __u64 %s = %s;\n", c.Name, cExpr(&c.Value, nil))
}

func emitScalarABIAssertions(b *strings.Builder) {
	b.WriteString(`
_Static_assert(sizeof(__u8) == 1, "horizon: __u8 width mismatch");
_Static_assert(sizeof(__u16) == 2, "horizon: __u16 width mismatch");
_Static_assert(sizeof(__u32) == 4, "horizon: __u32 width mismatch");
_Static_assert(sizeof(__u64) == 8, "horizon: __u64 width mismatch");
_Static_assert(sizeof(__s8) == 1, "horizon: __s8 width mismatch");
_Static_assert(sizeof(__s16) == 2, "horizon: __s16 width mismatch");
_Static_assert(sizeof(__s32) == 4, "horizon: __s32 width mismatch");
_Static_assert(sizeof(__s64) == 8, "horizon: __s64 width mismatch");
`)
}

func emitStruct(b *strings.Builder, decl ir.Struct, structs map[string]ir.Struct) {
	fmt.Fprintf(b, "\nstruct %s {\n", decl.Name)
	for _, field := range decl.Fields {
		if field.Type.Len != "" && field.Type.Elem != nil {
			fmt.Fprintf(b, "    %s %s[%s];\n", cType(*field.Type.Elem), field.Name, field.Type.Len)
			continue
		}
		fmt.Fprintf(b, "    %s %s;\n", cType(field.Type), field.Name)
	}
	b.WriteString("};\n")
	emitStructLayoutAssertions(b, decl, structs)
}

func emitStructLayoutAssertions(b *strings.Builder, decl ir.Struct, structs map[string]ir.Struct) {
	layout, ok := ir.StructLayout(decl, structs)
	if !ok {
		return
	}
	fmt.Fprintf(b, "_Static_assert(sizeof(struct %s) == %d, \"horizon: struct %s size mismatch\");\n", decl.Name, layout.Size, decl.Name)
	for _, field := range layout.Fields {
		fmt.Fprintf(b, "_Static_assert(__builtin_offsetof(struct %s, %s) == %d, \"horizon: struct %s.%s offset mismatch\");\n", decl.Name, field.Name, field.Offset, decl.Name, field.Name)
	}
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

func emitMapWrappers(b *strings.Builder, m ir.Map, methods map[string]bool) {
	if len(methods) == 0 {
		return
	}
	switch m.Kind {
	case ir.MapKindRingbuf:
		emitRingbufWrappers(b, m, methods)
	case ir.MapKindHash, ir.MapKindArray:
		emitLookupMapWrappers(b, m, methods)
	}
}

func emitRingbufWrappers(b *strings.Builder, m ir.Map, methods map[string]bool) {
	if m.Val.Name == "" {
		return
	}
	typ := "struct " + m.Val.Name
	if methods["reserve"] {
		fmt.Fprintf(b, `
static __always_inline %s *%s_reserve(void) {
    return bpf_ringbuf_reserve(&%s, sizeof(%s), 0);
}
`, typ, m.Name, m.Name, typ)
	}

	if methods["submit"] {
		fmt.Fprintf(b, `
static __always_inline void %s_submit(%s *value) {
    bpf_ringbuf_submit(value, 0);
}
`, m.Name, typ)
	}

	if methods["discard"] {
		fmt.Fprintf(b, `
static __always_inline void %s_discard(%s *value) {
    bpf_ringbuf_discard(value, 0);
}
`, m.Name, typ)
	}
}

func emitLookupMapWrappers(b *strings.Builder, m ir.Map, methods map[string]bool) {
	if m.Key.Name == "" || m.Val.Name == "" {
		return
	}
	keyType := cType(m.Key)
	valueType := cType(m.Val)
	if methods["lookup"] {
		fmt.Fprintf(b, `
static __always_inline %s *%s_lookup(%s key) {
    return bpf_map_lookup_elem(&%s, &key);
}
`, valueType, m.Name, keyType, m.Name)
	}

	if methods["update"] {
		fmt.Fprintf(b, `
static __always_inline long %s_update(%s key, %s value) {
    return bpf_map_update_elem(&%s, &key, &value, BPF_ANY);
}
`, m.Name, keyType, valueType, m.Name)
	}
	if methods["delete"] && m.Kind == ir.MapKindHash {
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
	case "untyped_int":
		return "__s64"
	default:
		if t.Name != "" {
			return cStructType(t.Name)
		}
		return "void"
	}
}

func cStructType(name string) string {
	switch name {
	case "xdp.Eth":
		return "struct hzn_xdp_eth"
	case "xdp.IPv4":
		return "struct hzn_xdp_ipv4"
	case "xdp.TCP":
		return "struct hzn_xdp_tcp"
	case "xdp.UDP":
		return "struct hzn_xdp_udp"
	default:
		return "struct " + name
	}
}

func cDecl(t ir.Type, name string) string {
	if t.Ptr && t.Elem != nil {
		return fmt.Sprintf("%s *%s", cType(*t.Elem), name)
	}
	return fmt.Sprintf("%s %s", cType(t), name)
}

func cContext(fn ir.Function) string {
	switch fn.Section.Kind {
	case ir.ProgramTracepoint:
		if fn.Section.Attach == "" {
			return "void *ctx"
		}
		event := fn.Section.Attach
		if idx := strings.IndexByte(event, ':'); idx >= 0 {
			event = event[idx+1:]
		}
		return "struct trace_event_raw_" + cIdent(event) + " *ctx"
	case ir.ProgramXDP:
		return "struct xdp_md *ctx"
	case ir.ProgramKprobe, ir.ProgramKretprobe:
		return "struct pt_regs *ctx"
	default:
		return "void *ctx"
	}
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
			fmt.Fprintf(b, "%s%s = %s;\n", indent, cDecl(typ, stmt.Name), cExpr(stmt.Value, env))
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
		if len(stmt.Else) > 0 {
			fmt.Fprintf(b, "%s} else {\n", indent)
			for _, child := range stmt.Else {
				emitStatement(b, child, program, depth+1, sourceMap, fn, env)
			}
			fmt.Fprintf(b, "%s}\n", indent)
			break
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
		return fmt.Sprintf("%s = %s", cDecl(typ, stmt.Name), cExpr(stmt.Value, env))
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
		if env != nil && env.constants[expr.Name] {
			return ir.Type{Name: "untyped_int"}, true
		}
		if env == nil {
			return ir.Type{}, false
		}
		return env.local(expr.Name)
	case "int":
		return ir.Type{Name: "i64"}, true
	case "nil":
		return ptrTo(ir.Type{}), true
	case "binary":
		return cBinaryExprType(expr, env)
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
			case "xdp.eth":
				return ptrTo(ir.Type{Name: "xdp.Eth"}), true
			case "xdp.ipv4":
				return ptrTo(ir.Type{Name: "xdp.IPv4"}), true
			case "xdp.tcp":
				return ptrTo(ir.Type{Name: "xdp.TCP"}), true
			case "xdp.udp":
				return ptrTo(ir.Type{Name: "xdp.UDP"}), true
			case "xdp.ntohs":
				return ir.Type{Name: "u16"}, true
			}
		}
		if mapName, ok := reserveCall(expr); ok {
			return ptrToMapValue(mapName, env), true
		}
		if mapName, ok := lookupCall(expr); ok {
			return ptrToMapValue(mapName, env), true
		}
	case "selector":
		if name := qualifiedName(expr); name != "" {
			if _, ok := xdpActionC(name); ok {
				return ir.Type{Name: "i32"}, true
			}
			if typ, ok := xdpConstantType(name); ok {
				return typ, true
			}
		}
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

func cBinaryExprType(expr *ir.Expr, env *cEnv) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	if isCBoolOp(expr.Op) {
		return ir.Type{Name: "bool"}, true
	}
	left, leftOK := cExprType(expr.Left, env)
	right, rightOK := cExprType(expr.Right, env)
	if !leftOK || !rightOK || !isCIntegerLike(left) || !isCIntegerLike(right) {
		return ir.Type{}, false
	}
	if expr.Op == "<<" || expr.Op == ">>" || left.Name != "untyped_int" {
		return left, true
	}
	if right.Name != "untyped_int" {
		return right, true
	}
	return ir.Type{Name: "i64"}, true
}

func isCBoolOp(op string) bool {
	switch op {
	case "==", "!=", "<", "<=", ">", ">=", "&&", "||":
		return true
	default:
		return false
	}
}

func isCIntegerLike(typ ir.Type) bool {
	switch typ.Name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "untyped_int":
		return true
	default:
		return false
	}
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
		if name := qualifiedName(expr); name != "" {
			if action, ok := xdpActionC(name); ok {
				return action
			}
			if constant, ok := xdpConstantC(name); ok {
				return constant
			}
		}
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
		return cBinaryOperand(expr.Left, env) + " " + expr.Op + " " + cBinaryOperand(expr.Right, env)
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

func cBinaryOperand(expr *ir.Expr, env *cEnv) string {
	if expr != nil && expr.Kind == "binary" {
		return "(" + cExpr(expr, env) + ")"
	}
	return cExpr(expr, env)
}

func xdpActionC(name string) (string, bool) {
	switch name {
	case "xdp.Aborted":
		return "XDP_ABORTED", true
	case "xdp.Drop":
		return "XDP_DROP", true
	case "xdp.Pass":
		return "XDP_PASS", true
	case "xdp.Tx":
		return "XDP_TX", true
	case "xdp.Redirect":
		return "XDP_REDIRECT", true
	default:
		return "", false
	}
}

func xdpConstantC(name string) (string, bool) {
	switch name {
	case "xdp.EtherTypeIPv4":
		return "bpf_htons(0x0800)", true
	case "xdp.IPProtoICMP":
		return "1", true
	case "xdp.IPProtoTCP":
		return "6", true
	case "xdp.IPProtoUDP":
		return "17", true
	default:
		return "", false
	}
}

func xdpConstantType(name string) (ir.Type, bool) {
	switch name {
	case "xdp.EtherTypeIPv4":
		return ir.Type{Name: "u16"}, true
	case "xdp.IPProtoICMP", "xdp.IPProtoTCP", "xdp.IPProtoUDP":
		return ir.Type{Name: "u8"}, true
	default:
		return ir.Type{}, false
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
		if _, ok := xdpPacketCall(expr); ok {
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
		case "xdp.eth":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("hzn_xdp_eth(%s)", cExpr(&arg, env))
			}
		case "xdp.ipv4":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("hzn_xdp_ipv4(%s)", cExpr(&arg, env))
			}
		case "xdp.tcp":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("hzn_xdp_tcp(%s)", cExpr(&arg, env))
			}
		case "xdp.udp":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("hzn_xdp_udp(%s)", cExpr(&arg, env))
			}
		case "xdp.ntohs":
			if len(expr.Args) == 1 {
				arg := expr.Args[0]
				return fmt.Sprintf("bpf_ntohs(%s)", cExpr(&arg, env))
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

func helperWrapperCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" {
		return "", false
	}
	switch qualifiedName(expr.Func) {
	case "bpf.current_pid":
		return "current_pid", true
	case "bpf.current_ppid":
		return "current_ppid", true
	case "bpf.current_uid":
		return "current_uid", true
	case "bpf.current_comm":
		return "current_comm", true
	default:
		return "", false
	}
}

func wrapperMethodCall(expr *ir.Expr) (string, string, bool) {
	if mapName, ok := reserveCall(expr); ok {
		return mapName, "reserve", true
	}
	if mapName, method, _, ok := consumeCall(expr); ok {
		return mapName, method, true
	}
	return mapMethodCall(expr)
}

func lookupCall(expr *ir.Expr) (string, bool) {
	mapName, method, ok := mapMethodCall(expr)
	return mapName, ok && method == "lookup"
}

func xdpPacketCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" || expr.Func.Operand.Name != "xdp" {
		return "", false
	}
	switch expr.Func.Field {
	case "eth", "ipv4", "tcp", "udp":
		return expr.Func.Field, true
	default:
		return "", false
	}
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
