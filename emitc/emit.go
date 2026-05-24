package emitc

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func Emit(program ir.Program) (Output, error) {
	if err := validateEmittable(program); err != nil {
		return Output{}, err
	}
	emitter := newCEmitter(program)
	if err := emitter.emit(); err != nil {
		return Output{}, err
	}
	return emitter.output(), nil
}

type cEmitter struct {
	program   ir.Program
	usage     cUsage
	sourceMap ir.SourceMap
	b         strings.Builder
	structs   map[string]ir.Struct
}

func newCEmitter(program ir.Program) *cEmitter {
	return &cEmitter{
		program:   program,
		usage:     analyzeUsage(program),
		sourceMap: newSourceMap(),
		structs:   ir.StructsByName(program.Structs),
	}
}

func (e *cEmitter) emit() error {
	e.emitPreamble()
	e.emitDeclarations()
	if err := e.emitFunctions(); err != nil {
		return err
	}
	e.sourceMap.Sources = sourceMapSources(e.sourceMap.Mappings)
	return nil
}

func (e *cEmitter) output() Output {
	return Output{Code: e.b.String(), SourceMap: e.sourceMap}
}

func (e *cEmitter) emitPreamble() {
	e.b.WriteString("#include \"vmlinux.h\"\n")
	if e.usage.hasBool() {
		e.b.WriteString("#include <stdbool.h>\n")
	}
	e.b.WriteString("#include <bpf/bpf_helpers.h>\n\n")
	e.b.WriteString("#include <bpf/bpf_tracing.h>\n\n")
	if e.usage.hasEndianHelpers() {
		e.b.WriteString("#include <bpf/bpf_endian.h>\n\n")
	}
	if programHasXDP(e.program) {
		emitXDPActionFallbacks(&e.b)
	}
	if programHasTC(e.program) {
		emitTCActionFallbacks(&e.b)
	}
	if programHasCgroup(e.program) {
		emitCgroupActionFallbacks(&e.b)
	}
	if programHasLSM(e.program) {
		emitLSMActionFallbacks(&e.b)
	}
	e.b.WriteString("char LICENSE[] SEC(\"license\") = \"GPL\";\n")
	emitScalarABIAssertions(&e.b)
	emitHelperWrappers(&e.b, e.usage)
	if e.usage.hasXDPPacketHelpers() {
		emitXDPPacketHelpers(&e.b, e.usage)
	}
}

func (e *cEmitter) emitDeclarations() {
	for _, c := range e.program.Constants {
		e.emitMapped(c.Span, "const", "", "", func() {
			emitConst(&e.b, c)
		})
	}
	for _, decl := range e.program.Structs {
		e.emitMapped(decl.Span, "struct", "", "", func() {
			emitStruct(&e.b, decl, e.structs)
		})
	}
	for _, m := range e.program.Maps {
		e.emitMapped(m.Span, "map", "", "", func() {
			emitMap(&e.b, m)
		})
	}
	for _, m := range e.program.Maps {
		e.emitMapped(m.Span, "map_wrapper", "", "", func() {
			emitMapWrappers(&e.b, m, e.usage.mapMethods[m.Name])
		})
	}
}

func (e *cEmitter) emitFunctions() error {
	for _, fn := range e.program.Functions {
		if err := e.emitFunction(fn); err != nil {
			return err
		}
	}
	return nil
}

func (e *cEmitter) emitFunction(fn ir.Function) error {
	env := newCEnv(e.program)
	for _, param := range fn.Params {
		env.setLocal(param.Name, param.Type)
	}
	startLine := generatedLine(&e.b)
	fmt.Fprintf(&e.b, "\nSEC(%q)\nint %s(%s) {\n", fn.Section.Name, fn.Name, cContext(fn))
	e.b.WriteString("    (void)ctx;\n")
	statements := cStatementEmitter{
		b:         &e.b,
		program:   e.program,
		sourceMap: &e.sourceMap,
		fn:        fn,
	}
	for _, stmt := range functionStatements(fn) {
		if err := statements.emit(stmt, 1, env); err != nil {
			return err
		}
	}
	e.b.WriteString("}\n")
	addSourceMapping(&e.sourceMap, fn.Span, "function", fn.Name, fn.Section.Name, startLine, generatedLine(&e.b))
	return nil
}

func (e *cEmitter) emitMapped(source span.Span, node string, function string, section string, emit func()) {
	emitMapped(&e.b, &e.sourceMap, source, node, function, section, emit)
}

func newSourceMap() ir.SourceMap {
	return ir.SourceMap{
		Schema:    "m31labs.dev/horizon/sourcemap/v0",
		Generated: ir.GeneratedSource{Language: "c"},
	}
}

func emitMapped(b *strings.Builder, sourceMap *ir.SourceMap, source span.Span, node string, function string, section string, emit func()) {
	startLine := generatedLine(b)
	emit()
	addSourceMapping(sourceMap, source, node, function, section, startLine, generatedLine(b))
}

func addSourceMapping(sourceMap *ir.SourceMap, source span.Span, node string, function string, section string, startLine int, endLine int) {
	if sourceMap == nil || source.IsZero() || startLine == endLine {
		return
	}
	sourceMap.Mappings = append(sourceMap.Mappings, ir.SourceMapping{
		Source:   source,
		Function: function,
		Section:  section,
		Node:     node,
		Generated: span.Span{
			Start: span.Point{Line: startLine, Column: 1},
			End:   span.Point{Line: endLine, Column: 1},
		},
	})
}

func generatedLine(b *strings.Builder) int {
	if b == nil {
		return 1
	}
	return strings.Count(b.String(), "\n") + 1
}

type cEnv struct {
	parent    *cEnv
	ptrLocals map[string]bool
	locals    map[string]ir.Type
	constants map[string]ir.Type
	structs   map[string]ir.Struct
	maps      map[string]ir.Map
}

func newCEnv(program ir.Program) *cEnv {
	env := &cEnv{
		ptrLocals: map[string]bool{},
		locals:    map[string]ir.Type{},
		constants: map[string]ir.Type{},
		structs:   map[string]ir.Struct{},
		maps:      map[string]ir.Map{},
	}
	for _, decl := range program.Constants {
		env.constants[decl.Name] = constType(decl)
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

func (e *cEnv) child() *cEnv {
	if e == nil {
		return nil
	}
	return &cEnv{
		parent:    e,
		ptrLocals: map[string]bool{},
		locals:    map[string]ir.Type{},
		constants: e.constants,
		structs:   e.structs,
		maps:      e.maps,
	}
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
	if ptr, ok := e.ptrLocals[name]; ok {
		return ptr
	}
	if e.parent == nil {
		return false
	}
	return e.parent.isPtr(name)
}

func (e *cEnv) local(name string) (ir.Type, bool) {
	if e == nil {
		return ir.Type{}, false
	}
	if typ, ok := e.locals[name]; ok {
		return typ, true
	}
	if e.parent == nil {
		return ir.Type{}, false
	}
	return e.parent.local(name)
}

func (e *cEnv) hasLocal(name string) bool {
	_, ok := e.local(name)
	return ok
}

type cUsage struct {
	helpers       map[string]bool
	mapMethods    map[string]map[string]bool
	xdpHelpers    map[string]bool
	cgroupHelpers map[string]bool
	maps          map[string]ir.Map
	boolTypes     bool
}

func analyzeUsage(program ir.Program) cUsage {
	usage := newCUsage()
	usage.walkProgram(program)
	usage.expandXDPPacketDependencies()
	return usage
}

func newCUsage() cUsage {
	return cUsage{
		helpers:       map[string]bool{},
		mapMethods:    map[string]map[string]bool{},
		xdpHelpers:    map[string]bool{},
		cgroupHelpers: map[string]bool{},
		maps:          map[string]ir.Map{},
	}
}

func (u *cUsage) walkProgram(program ir.Program) {
	for _, m := range program.Maps {
		u.walkMap(m)
	}
	for _, c := range program.Constants {
		u.walkConst(c)
	}
	for _, typ := range program.Structs {
		u.walkStruct(typ)
	}
	for _, fn := range program.Functions {
		u.walkFunction(fn)
	}
}

func (u *cUsage) walkMap(m ir.Map) {
	u.maps[m.Name] = m
	if typeUsesBool(m.Key) || typeUsesBool(m.Val) {
		u.boolTypes = true
	}
}

func (u *cUsage) walkConst(c ir.Const) {
	if c.Value.Kind == "bool" {
		u.boolTypes = true
	}
}

func (u *cUsage) walkStruct(typ ir.Struct) {
	for _, field := range typ.Fields {
		if typeUsesBool(field.Type) {
			u.boolTypes = true
		}
	}
}

func (u *cUsage) walkFunction(fn ir.Function) {
	if typeUsesBool(fn.Return) {
		u.boolTypes = true
	}
	for _, param := range fn.Params {
		if typeUsesBool(param.Type) {
			u.boolTypes = true
		}
	}
	u.walkStatements(functionStatements(fn))
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
		u.walkBranch(stmt)
	case "for":
		u.walkFor(stmt)
	case "raw":
		u.walkExpr(stmt.Value)
	}
}

func (u *cUsage) walkBranch(stmt ir.Statement) {
	u.walkExpr(stmt.Cond)
	u.walkStatements(stmt.Then)
	u.walkStatements(stmt.Else)
}

func (u *cUsage) walkFor(stmt ir.Statement) {
	if stmt.Init != nil {
		u.walkStatement(*stmt.Init)
	}
	u.walkExpr(stmt.Cond)
	if stmt.Post != nil {
		u.walkStatement(*stmt.Post)
	}
	u.walkStatements(stmt.Body)
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
	u.observeExpr(expr)
	u.walkExprChildren(expr)
}

func (u *cUsage) observeExpr(expr *ir.Expr) {
	if expr.Kind == "bool" {
		u.boolTypes = true
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
	if helper, ok := cgroupHelperCall(expr); ok {
		u.cgroupHelpers[helper] = true
	}
}

func (u *cUsage) walkExprChildren(expr *ir.Expr) {
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

func (u cUsage) hasEndianHelpers() bool {
	return len(u.xdpHelpers) > 0 || u.cgroupHelpers["dst_port"]
}

func (u cUsage) hasBool() bool {
	return u.boolTypes
}

func typeUsesBool(typ ir.Type) bool {
	if typ.Name == "bool" {
		return true
	}
	if typ.Elem != nil && typeUsesBool(*typ.Elem) {
		return true
	}
	for _, arg := range typ.Args {
		if typeUsesBool(arg) {
			return true
		}
	}
	return false
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

func emitTCActionFallbacks(b *strings.Builder) {
	b.WriteString(`#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7
#endif

`)
}

func programHasTC(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramTC {
			return true
		}
	}
	return false
}

func emitCgroupActionFallbacks(b *strings.Builder) {
	b.WriteString(`#ifndef HZN_CGROUP_DENY
#define HZN_CGROUP_DENY 0
#define HZN_CGROUP_ALLOW 1
#endif

`)
}

func programHasCgroup(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramCgroup {
			return true
		}
	}
	return false
}

func emitLSMActionFallbacks(b *strings.Builder) {
	b.WriteString(`#ifndef EPERM
#define EPERM 1
#endif
#ifndef HZN_LSM_ALLOW
#define HZN_LSM_ALLOW 0
#define HZN_LSM_DENY (-EPERM)
#endif

`)
}

func programHasLSM(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramLSM {
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
	fmt.Fprintf(b, "\nstatic const %s %s = %s;\n", cType(constType(c)), cConstName(c.Name), cExpr(&c.Value, nil))
}

func constType(c ir.Const) ir.Type {
	if c.Type.Name != "" || c.Type.Elem != nil || c.Type.Len != "" || c.Type.Ptr || len(c.Type.Args) > 0 {
		return c.Type
	}
	switch c.Value.Kind {
	case "bool":
		return ir.Type{Name: "bool"}
	default:
		return ir.Type{Name: "u64"}
	}
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
	fmt.Fprintf(b, "\nstruct %s {\n", cStructName(decl.Name))
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
	cName := cStructName(decl.Name)
	fmt.Fprintf(b, "_Static_assert(sizeof(struct %s) == %d, \"horizon: struct %s size mismatch\");\n", cName, layout.Size, decl.Name)
	for _, field := range layout.Fields {
		fmt.Fprintf(b, "_Static_assert(__builtin_offsetof(struct %s, %s) == %d, \"horizon: struct %s.%s offset mismatch\");\n", cName, field.Name, field.Offset, decl.Name, field.Name)
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
	typ := cType(m.Val)
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
		return "struct " + cStructName(name)
	}
}

func cStructName(name string) string {
	return "hzn_type_" + cIdent(name)
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
	case ir.ProgramTC:
		return "struct __sk_buff *ctx"
	case ir.ProgramCgroup:
		return "struct bpf_sock_addr *ctx"
	case ir.ProgramLSM:
		return "void *ctx"
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

func cConstName(name string) string {
	return "hzn_const_" + cIdent(name)
}

type cStatementEmitter struct {
	b         *strings.Builder
	program   ir.Program
	sourceMap *ir.SourceMap
	fn        ir.Function
}

func (e cStatementEmitter) emit(stmt ir.Statement, depth int, env *cEnv) error {
	startLine := generatedLine(e.b)
	if err := e.emitKind(stmt, depth, env); err != nil {
		return err
	}
	e.addMapping(stmt, startLine)
	return nil
}

func (e cStatementEmitter) emitKind(stmt ir.Statement, depth int, env *cEnv) error {
	switch stmt.Kind {
	case "short_var":
		e.emitShortVar(stmt, depth, env)
	case "assign":
		e.emitAssign(stmt, depth, env)
	case "expr":
		e.emitExprStatement(stmt, depth, env)
	case "return":
		e.emitReturn(stmt, depth, env)
	case "if":
		return e.emitIf(stmt, depth, env)
	case "for":
		return e.emitFor(stmt, depth, env)
	case "inc":
		e.emitInc(stmt, depth)
	case "raw":
		return unsupportedStatement(stmt, "raw")
	default:
		return unsupportedStatement(stmt, stmt.Kind)
	}
	return nil
}

func (e cStatementEmitter) emitShortVar(stmt ir.Statement, depth int, env *cEnv) {
	indent := indent(depth)
	if mapName, ok := reserveCall(stmt.Value); ok {
		fmt.Fprintf(e.b, "%s%s *%s = %s_reserve();\n", indent, reserveType(mapName, e.program.Maps), stmt.Name, mapName)
		env.setLocal(stmt.Name, ptrToMapValue(mapName, env))
		return
	}
	if mapName, ok := lookupCall(stmt.Value); ok {
		fmt.Fprintf(e.b, "%s%s *%s = %s;\n", indent, mapValueType(mapName, e.program.Maps), stmt.Name, cExpr(stmt.Value, env))
		env.setLocal(stmt.Name, ptrToMapValue(mapName, env))
		return
	}
	typ := inferredExprType(stmt.Value, env)
	fmt.Fprintf(e.b, "%s%s = %s;\n", indent, cDecl(typ, stmt.Name), cExpr(stmt.Value, env))
	env.setLocal(stmt.Name, typ)
}

func (e cStatementEmitter) emitAssign(stmt ir.Statement, depth int, env *cEnv) {
	fmt.Fprintf(e.b, "%s%s = %s;\n", indent(depth), cExpr(stmt.Target, env), cExpr(stmt.Value, env))
	if stmt.Target != nil && stmt.Target.Kind == "ident" {
		env.setLocal(stmt.Target.Name, inferredExprType(stmt.Value, env))
	}
}

func (e cStatementEmitter) emitExprStatement(stmt ir.Statement, depth int, env *cEnv) {
	indent := indent(depth)
	if mapName, op, varName, ok := consumeCall(stmt.Expr); ok {
		fmt.Fprintf(e.b, "%s%s_%s(%s);\n", indent, mapName, op, varName)
		return
	}
	fmt.Fprintf(e.b, "%s%s;\n", indent, cExpr(stmt.Expr, env))
}

func (e cStatementEmitter) emitReturn(stmt ir.Statement, depth int, env *cEnv) {
	fmt.Fprintf(e.b, "%sreturn %s;\n", indent(depth), cExpr(stmt.Value, env))
}

func (e cStatementEmitter) emitIf(stmt ir.Statement, depth int, env *cEnv) error {
	indent := indent(depth)
	fmt.Fprintf(e.b, "%sif (%s) {\n", indent, cExpr(stmt.Cond, env))
	if err := e.emitChildren(stmt.Then, depth+1, env.child()); err != nil {
		return err
	}
	if len(stmt.Else) == 0 {
		fmt.Fprintf(e.b, "%s}\n", indent)
		return nil
	}
	fmt.Fprintf(e.b, "%s} else {\n", indent)
	if err := e.emitChildren(stmt.Else, depth+1, env.child()); err != nil {
		return err
	}
	fmt.Fprintf(e.b, "%s}\n", indent)
	return nil
}

func (e cStatementEmitter) emitFor(stmt ir.Statement, depth int, env *cEnv) error {
	indent := indent(depth)
	loopEnv := env.child()
	switch {
	case stmt.Init != nil || stmt.Post != nil:
		fmt.Fprintf(e.b, "%sfor (%s; %s; %s) {\n", indent, cForInit(stmt.Init, loopEnv, loopIndexType(stmt, loopEnv)), cExpr(stmt.Cond, loopEnv), cForPost(stmt.Post))
	case stmt.Cond == nil || stmt.Cond.Kind == "":
		fmt.Fprintf(e.b, "%sfor (;;) {\n", indent)
	default:
		fmt.Fprintf(e.b, "%sfor (; %s; ) {\n", indent, cExpr(stmt.Cond, loopEnv))
	}
	if err := e.emitChildren(stmt.Body, depth+1, loopEnv.child()); err != nil {
		return err
	}
	fmt.Fprintf(e.b, "%s}\n", indent)
	return nil
}

func (e cStatementEmitter) emitInc(stmt ir.Statement, depth int) {
	fmt.Fprintf(e.b, "%s%s%s;\n", indent(depth), stmt.Name, stmt.Op)
}

func (e cStatementEmitter) emitChildren(stmts []ir.Statement, depth int, env *cEnv) error {
	for _, child := range stmts {
		if err := e.emit(child, depth, env); err != nil {
			return err
		}
	}
	return nil
}

func (e cStatementEmitter) addMapping(stmt ir.Statement, startLine int) {
	if e.sourceMap == nil || stmt.Span.IsZero() {
		return
	}
	e.sourceMap.Mappings = append(e.sourceMap.Mappings, ir.SourceMapping{
		Source:   stmt.Span,
		Function: e.fn.Name,
		Section:  e.fn.Section.Name,
		Node:     stmt.Kind,
		Generated: span.Span{
			Start: span.Point{Line: startLine, Column: 1},
			End:   span.Point{Line: generatedLine(e.b), Column: 1},
		},
	})
}

func indent(depth int) string {
	return strings.Repeat("    ", depth)
}

func reserveType(mapName string, maps []ir.Map) string {
	for _, m := range maps {
		if m.Name == mapName && m.Val.Name != "" {
			return cType(m.Val)
		}
	}
	return "void"
}

func cForInit(stmt *ir.Statement, env *cEnv, typeHint ir.Type) string {
	if stmt == nil {
		return ""
	}
	switch stmt.Kind {
	case "short_var":
		typ := inferredExprType(stmt.Value, env)
		if !typeHintIsZero(typeHint) {
			typ = typeHint
		}
		env.setLocal(stmt.Name, typ)
		return fmt.Sprintf("%s = %s", cDecl(typ, stmt.Name), cExpr(stmt.Value, env))
	case "assign":
		return fmt.Sprintf("%s = %s", cExpr(stmt.Target, env), cExpr(stmt.Value, env))
	default:
		return ""
	}
}

func loopIndexType(stmt ir.Statement, env *cEnv) ir.Type {
	if stmt.Init == nil || stmt.Init.Kind != "short_var" || stmt.Init.Name == "" {
		return ir.Type{}
	}
	if stmt.Cond == nil || stmt.Cond.Kind != "binary" || stmt.Cond.Left == nil || stmt.Cond.Right == nil {
		return ir.Type{}
	}
	if stmt.Cond.Left.Kind != "ident" || stmt.Cond.Left.Name != stmt.Init.Name {
		return ir.Type{}
	}
	typ, ok := cExprType(stmt.Cond.Right, env)
	if !ok || !isCIntegerLike(typ) || typ.Name == "untyped_int" {
		return ir.Type{}
	}
	return typ
}

func typeHintIsZero(typ ir.Type) bool {
	return typ.Name == "" && len(typ.Args) == 0 && typ.Len == "" && typ.Elem == nil && !typ.Ptr
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
	return cExprTyper{env: env}.typeOf(expr)
}

type cExprTyper struct {
	env *cEnv
}

func (t cExprTyper) typeOf(expr *ir.Expr) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	switch expr.Kind {
	case "ident":
		return t.ident(expr)
	case "int":
		return ir.Type{Name: "i64"}, true
	case "bool":
		return ir.Type{Name: "bool"}, true
	case "nil":
		return ptrTo(ir.Type{}), true
	case "binary":
		return t.binary(expr)
	case "struct_lit":
		return t.structLiteral(expr)
	case "call":
		return t.call(expr)
	case "selector":
		return t.selector(expr)
	case "unary":
		return t.unary(expr)
	}
	return ir.Type{}, false
}

func (t cExprTyper) ident(expr *ir.Expr) (ir.Type, bool) {
	if t.env != nil {
		if typ, ok := t.env.constants[expr.Name]; ok {
			return typ, true
		}
	}
	if t.env == nil {
		return ir.Type{}, false
	}
	return t.env.local(expr.Name)
}

func (t cExprTyper) structLiteral(expr *ir.Expr) (ir.Type, bool) {
	if expr.Name == "" {
		return ir.Type{}, false
	}
	return ir.Type{Name: expr.Name}, true
}

func (t cExprTyper) call(expr *ir.Expr) (ir.Type, bool) {
	if name := qualifiedName(expr.Func); name != "" {
		if isScalarConversionCall(expr) {
			return ir.Type{Name: name}, true
		}
		if typ, ok := knownCallType(name); ok {
			return typ, true
		}
	}
	if mapName, ok := reserveCall(expr); ok {
		return ptrToMapValue(mapName, t.env), true
	}
	if mapName, ok := lookupCall(expr); ok {
		return ptrToMapValue(mapName, t.env), true
	}
	if _, method, ok := mapMethodCall(expr); ok {
		switch method {
		case "update", "delete":
			return ir.Type{Name: "i64"}, true
		}
	}
	return ir.Type{}, false
}

func knownCallType(name string) (ir.Type, bool) {
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
	case "cgroup.dst_port":
		return ir.Type{Name: "u16"}, true
	default:
		return ir.Type{}, false
	}
}

func (t cExprTyper) selector(expr *ir.Expr) (ir.Type, bool) {
	if name := qualifiedName(expr); name != "" {
		if typ, ok := knownSelectorType(name); ok {
			return typ, true
		}
	}
	return t.fieldSelector(expr)
}

func knownSelectorType(name string) (ir.Type, bool) {
	if _, ok := xdpActionC(name); ok {
		return ir.Type{Name: "i32"}, true
	}
	if _, ok := tcActionC(name); ok {
		return ir.Type{Name: "i32"}, true
	}
	if _, ok := cgroupActionC(name); ok {
		return ir.Type{Name: "i32"}, true
	}
	if _, ok := lsmActionC(name); ok {
		return ir.Type{Name: "i32"}, true
	}
	if typ, ok := xdpConstantType(name); ok {
		return typ, true
	}
	return ir.Type{}, false
}

func (t cExprTyper) unary(expr *ir.Expr) (ir.Type, bool) {
	switch expr.Op {
	case "&":
		operand, ok := t.typeOf(expr.Operand)
		if !ok {
			return ir.Type{}, false
		}
		return ptrTo(operand), true
	case "!":
		return ir.Type{Name: "bool"}, true
	case "*":
		operand, ok := t.typeOf(expr.Operand)
		if !ok || !operand.Ptr || operand.Elem == nil {
			return ir.Type{}, false
		}
		return *operand.Elem, true
	default:
		return ir.Type{}, false
	}
}

func cBinaryExprType(expr *ir.Expr, env *cEnv) (ir.Type, bool) {
	return cExprTyper{env: env}.binary(expr)
}

func (t cExprTyper) binary(expr *ir.Expr) (ir.Type, bool) {
	if expr == nil {
		return ir.Type{}, false
	}
	if isCBoolOp(expr.Op) {
		return ir.Type{Name: "bool"}, true
	}
	left, leftOK := t.typeOf(expr.Left)
	right, rightOK := t.typeOf(expr.Right)
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
	return cExprTyper{env: env}.fieldSelector(expr)
}

func (t cExprTyper) fieldSelector(expr *ir.Expr) (ir.Type, bool) {
	if expr == nil || expr.Operand == nil {
		return ir.Type{}, false
	}
	operand, ok := t.typeOf(expr.Operand)
	if !ok {
		return ir.Type{}, false
	}
	if operand.Ptr && operand.Elem != nil {
		operand = *operand.Elem
	}
	if t.env == nil {
		return ir.Type{}, false
	}
	structDecl, ok := t.env.structs[operand.Name]
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
	return cExprEmitter{env: env}.emit(expr)
}

type cExprEmitter struct {
	env *cEnv
}

func (e cExprEmitter) emit(expr *ir.Expr) string {
	if expr == nil {
		return "0"
	}
	switch expr.Kind {
	case "ident":
		return e.ident(expr)
	case "int":
		return expr.Value
	case "bool":
		return expr.Value
	case "nil":
		return "0"
	case "selector":
		return e.selector(expr)
	case "unary":
		return expr.Op + e.emit(expr.Operand)
	case "binary":
		return e.binary(expr)
	case "call":
		return e.call(expr)
	case "struct_lit":
		return e.structLiteral(expr)
	case "raw":
		return expr.Value
	default:
		return "0"
	}
}

func (e cExprEmitter) ident(expr *ir.Expr) string {
	if e.env != nil {
		if _, ok := e.env.constants[expr.Name]; ok {
			return cConstName(expr.Name)
		}
	}
	return expr.Name
}

func (e cExprEmitter) selector(expr *ir.Expr) string {
	if name := qualifiedName(expr); name != "" {
		if symbol, ok := knownSelectorC(name); ok {
			return symbol
		}
	}
	if expr.Operand == nil {
		return expr.Field
	}
	access := "."
	if e.isPointer(expr.Operand) {
		access = "->"
	}
	return e.emit(expr.Operand) + access + expr.Field
}

func knownSelectorC(name string) (string, bool) {
	if action, ok := xdpActionC(name); ok {
		return action, true
	}
	if action, ok := tcActionC(name); ok {
		return action, true
	}
	if action, ok := cgroupActionC(name); ok {
		return action, true
	}
	if action, ok := lsmActionC(name); ok {
		return action, true
	}
	if constant, ok := xdpConstantC(name); ok {
		return constant, true
	}
	return "", false
}

func (e cExprEmitter) binary(expr *ir.Expr) string {
	return e.binaryOperand(expr.Left) + " " + expr.Op + " " + e.binaryOperand(expr.Right)
}

func cBinaryOperand(expr *ir.Expr, env *cEnv) string {
	return cExprEmitter{env: env}.binaryOperand(expr)
}

func (e cExprEmitter) binaryOperand(expr *ir.Expr) string {
	if expr != nil && expr.Kind == "binary" {
		return "(" + e.emit(expr) + ")"
	}
	return e.emit(expr)
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

func tcActionC(name string) (string, bool) {
	switch name {
	case "tc.OK":
		return "TC_ACT_OK", true
	case "tc.Reclassify":
		return "TC_ACT_RECLASSIFY", true
	case "tc.Shot":
		return "TC_ACT_SHOT", true
	case "tc.Pipe":
		return "TC_ACT_PIPE", true
	case "tc.Stolen":
		return "TC_ACT_STOLEN", true
	case "tc.Redirect":
		return "TC_ACT_REDIRECT", true
	default:
		return "", false
	}
}

func cgroupActionC(name string) (string, bool) {
	switch name {
	case "cgroup.Allow":
		return "HZN_CGROUP_ALLOW", true
	case "cgroup.Deny":
		return "HZN_CGROUP_DENY", true
	default:
		return "", false
	}
}

func lsmActionC(name string) (string, bool) {
	switch name {
	case "lsm.Allow":
		return "HZN_LSM_ALLOW", true
	case "lsm.Deny":
		return "HZN_LSM_DENY", true
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
	return cExprEmitter{env: env}.isPointer(expr)
}

func (e cExprEmitter) isPointer(expr *ir.Expr) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case "ident":
		return e.env.isPtr(expr.Name)
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
	return cExprEmitter{env: env}.structLiteral(expr)
}

func (e cExprEmitter) structLiteral(expr *ir.Expr) string {
	if expr == nil || expr.Name == "" {
		return "(void){0}"
	}
	if len(expr.Fields) == 0 {
		return fmt.Sprintf("(%s){0}", cType(ir.Type{Name: expr.Name}))
	}
	fields := make([]string, 0, len(expr.Fields))
	for _, field := range expr.Fields {
		value := field.Value
		fields = append(fields, fmt.Sprintf(".%s = %s", field.Name, e.emit(&value)))
	}
	return fmt.Sprintf("(%s){ %s }", cType(ir.Type{Name: expr.Name}), strings.Join(fields, ", "))
}

func cCallExpr(expr *ir.Expr, env *cEnv) string {
	return cExprEmitter{env: env}.call(expr)
}

func (e cExprEmitter) call(expr *ir.Expr) string {
	if expr == nil || expr.Kind != "call" {
		return "0"
	}
	if isScalarConversionCall(expr) && len(expr.Args) == 1 {
		arg := expr.Args[0]
		return fmt.Sprintf("(%s)(%s)", cType(ir.Type{Name: qualifiedName(expr.Func)}), e.emit(&arg))
	}
	if mapName, method, ok := mapMethodCall(expr); ok {
		return fmt.Sprintf("%s_%s(%s)", mapName, method, e.args(expr.Args))
	}
	if name := qualifiedName(expr.Func); name != "" {
		if rendered, ok := e.knownCall(expr, name); ok {
			return rendered
		}
	}
	return e.emit(expr.Func) + "(" + e.args(expr.Args) + ")"
}

func (e cExprEmitter) knownCall(expr *ir.Expr, name string) (string, bool) {
	switch name {
	case "bpf.current_pid":
		return "hzn_current_pid()", true
	case "bpf.current_ppid":
		return "hzn_current_ppid()", true
	case "bpf.current_uid":
		return "hzn_current_uid()", true
	case "bpf.current_comm":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("hzn_current_comm(%s, sizeof(%s))", e.emit(&arg), sizeofExpr(&arg, e.env))
		})
	case "xdp.eth":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("hzn_xdp_eth(%s)", e.emit(&arg))
		})
	case "xdp.ipv4":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("hzn_xdp_ipv4(%s)", e.emit(&arg))
		})
	case "xdp.tcp":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("hzn_xdp_tcp(%s)", e.emit(&arg))
		})
	case "xdp.udp":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("hzn_xdp_udp(%s)", e.emit(&arg))
		})
	case "xdp.ntohs":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("bpf_ntohs(%s)", e.emit(&arg))
		})
	case "cgroup.dst_port":
		return e.oneArgCall(expr, func(arg ir.Expr) string {
			return fmt.Sprintf("bpf_ntohs((__u16)%s->user_port)", e.emit(&arg))
		})
	default:
		return "", false
	}
}

func (e cExprEmitter) oneArgCall(expr *ir.Expr, render func(ir.Expr) string) (string, bool) {
	if len(expr.Args) != 1 {
		return "", false
	}
	return render(expr.Args[0]), true
}

func (e cExprEmitter) args(in []ir.Expr) string {
	args := make([]string, 0, len(in))
	for _, arg := range in {
		arg := arg
		args = append(args, e.emit(&arg))
	}
	return strings.Join(args, ", ")
}

func isScalarConversionCall(expr *ir.Expr) bool {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "ident" {
		return false
	}
	return isIntegerScalarType(expr.Func.Name)
}

func isIntegerScalarType(name string) bool {
	switch name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64":
		return true
	default:
		return false
	}
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

func cgroupHelperCall(expr *ir.Expr) (string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" || expr.Func.Operand.Name != "cgroup" {
		return "", false
	}
	switch expr.Func.Field {
	case "dst_port":
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
