package ast

import (
	"testing"

	"m31labs.dev/horizon/parser"
)

func TestBuildExecwatchAST(t *testing.T) {
	parsed, err := parser.ParsePath("../examples/execwatch/exec.hzn")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if file.Package != "probes" {
		t.Fatalf("package = %q, want probes", file.Package)
	}
	if len(file.Imports) != 1 {
		t.Fatalf("imports = %d, want 1", len(file.Imports))
	}
	if got, want := file.Imports[0].Alias, "bpf"; got != want {
		t.Fatalf("import alias = %q, want %q", got, want)
	}
	if len(file.Decls) != 3 {
		t.Fatalf("decls = %d, want 3", len(file.Decls))
	}

	typeDecl, ok := file.Decls[0].(TypeDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want TypeDecl", file.Decls[0])
	}
	if typeDecl.Name != "ExecEvent" {
		t.Fatalf("type name = %q, want ExecEvent", typeDecl.Name)
	}
	if len(typeDecl.Fields) != 5 {
		t.Fatalf("fields = %d, want 5", len(typeDecl.Fields))
	}
	if ts := typeDecl.Fields[0]; ts.Name != "ts_ns" || ts.Type.Name != "u64" {
		t.Fatalf("ts_ns field = %#v, want u64", ts)
	}
	comm := typeDecl.Fields[4]
	if comm.Name != "comm" || comm.Type.Len != "16" || comm.Type.Elem == nil || comm.Type.Elem.Name != "u8" {
		t.Fatalf("comm field = %#v, want [16]u8", comm)
	}

	mapDecl, ok := file.Decls[1].(MapDecl)
	if !ok {
		t.Fatalf("decl[1] = %T, want MapDecl", file.Decls[1])
	}
	if mapDecl.Name != "ExecEvents" || mapDecl.Kind != MapKindRingbuf || mapDecl.Val.Name != "ExecEvent" {
		t.Fatalf("map decl = %#v, want ringbuf ExecEvent", mapDecl)
	}

	fn, ok := file.Decls[2].(FuncDecl)
	if !ok {
		t.Fatalf("decl[2] = %T, want FuncDecl", file.Decls[2])
	}
	if fn.Name != "OnExec" || fn.Return.Name != "i32" {
		t.Fatalf("func = %#v, want OnExec returning i32", fn)
	}
	if len(fn.Attrs) != 2 || fn.Attrs[0].Name != "capability" || fn.Attrs[1].Name != "tracepoint" {
		t.Fatalf("attrs = %#v, want capability and tracepoint", fn.Attrs)
	}
	if len(fn.Params) != 1 || fn.Params[0].Name != "ctx" || fn.Params[0].Type.Name != "tracepoint.Exec" {
		t.Fatalf("params = %#v, want ctx tracepoint.Exec", fn.Params)
	}
	if len(fn.Body) == 0 {
		t.Fatal("func body is empty")
	}
	if len(fn.Body) != 9 {
		t.Fatalf("body statements = %d, want 9", len(fn.Body))
	}
	if _, ok := fn.Body[0].(ShortVarStmt); !ok {
		t.Fatalf("body[0] = %T, want ShortVarStmt", fn.Body[0])
	}
	if _, ok := fn.Body[1].(IfStmt); !ok {
		t.Fatalf("body[1] = %T, want IfStmt", fn.Body[1])
	}
	if _, ok := fn.Body[2].(AssignStmt); !ok {
		t.Fatalf("body[2] = %T, want AssignStmt", fn.Body[2])
	}
	if _, ok := fn.Body[6].(ExprStmt); !ok {
		t.Fatalf("body[6] = %T, want ExprStmt", fn.Body[6])
	}
	if _, ok := fn.Body[7].(ExprStmt); !ok {
		t.Fatalf("body[7] = %T, want ExprStmt", fn.Body[7])
	}
	if _, ok := fn.Body[8].(ReturnStmt); !ok {
		t.Fatalf("body[8] = %T, want ReturnStmt", fn.Body[8])
	}
}

func TestBuildTypeAlias(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package probes

type Port = u16
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	decl, ok := file.Decls[0].(TypeDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want TypeDecl", file.Decls[0])
	}
	if decl.Name != "Port" || !decl.IsAlias() || decl.Alias.Name != "u16" {
		t.Fatalf("alias decl = %#v, want Port = u16", decl)
	}
	if len(decl.Fields) != 0 {
		t.Fatalf("fields = %#v, want none for alias", decl.Fields)
	}
}

func TestBuildTypeGroup(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package probes

type (
    Pid = u32
    Event struct {
        pid Pid
    }
)
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	group, ok := file.Decls[0].(TypeGroupDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want TypeGroupDecl", file.Decls[0])
	}
	if len(group.Types) != 2 {
		t.Fatalf("types = %#v, want two", group.Types)
	}
	if group.Types[0].Name != "Pid" || group.Types[0].Alias.Name != "u32" {
		t.Fatalf("type[0] = %#v, want Pid = u32", group.Types[0])
	}
	if group.Types[1].Name != "Event" || len(group.Types[1].Fields) != 1 || group.Types[1].Fields[0].Type.Name != "Pid" {
		t.Fatalf("type[1] = %#v, want Event struct with pid Pid", group.Types[1])
	}
}

func TestBuildCapabilityAlias(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package probes

capability ExecObserve = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 2 {
		t.Fatalf("decls = %d, want capability alias and function", len(file.Decls))
	}
	capabilityDecl, ok := file.Decls[0].(CapabilityDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want CapabilityDecl", file.Decls[0])
	}
	if capabilityDecl.Name != "ExecObserve" || capabilityDecl.Value != "kernel.process.exec.observe" {
		t.Fatalf("capability decl = %#v, want ExecObserve alias", capabilityDecl)
	}
	fn := file.Decls[1].(FuncDecl)
	arg, ok := fn.Attrs[0].Args[0].(IdentExpr)
	if !ok || arg.Name != "ExecObserve" {
		t.Fatalf("capability attr arg = %#v, want ExecObserve identifier", fn.Attrs[0].Args)
	}
}

func TestBuildBoundedForClause(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    for i := 0; i < 4; i++ {
        bpf.current_pid()
    }
    return 0
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	loop, ok := fn.Body[0].(ForStmt)
	if !ok {
		t.Fatalf("body[0] = %T, want ForStmt", fn.Body[0])
	}
	init, ok := loop.Init.(ShortVarStmt)
	if !ok || init.Name != "i" {
		t.Fatalf("loop init = %#v, want short var i", loop.Init)
	}
	cond, ok := loop.Cond.(BinaryExpr)
	if !ok || cond.Op != "<" {
		t.Fatalf("loop cond = %#v, want < binary expr", loop.Cond)
	}
	post, ok := loop.Post.(IncStmt)
	if !ok || post.Name != "i" || post.Op != "++" {
		t.Fatalf("loop post = %#v, want i++", loop.Post)
	}
}

func TestBuildIfInitStatement(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@xdp
func F(ctx xdp.Context) i32 {
    if tcp := xdp.tcp(ctx); tcp != nil {
        return xdp.Drop
    }
    return xdp.Pass
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	stmt, ok := fn.Body[0].(IfStmt)
	if !ok {
		t.Fatalf("body[0] = %T, want IfStmt", fn.Body[0])
	}
	init, ok := stmt.Init.(ShortVarStmt)
	if !ok || init.Name != "tcp" {
		t.Fatalf("if init = %#v, want short var tcp", stmt.Init)
	}
	cond, ok := stmt.Cond.(BinaryExpr)
	if !ok || cond.Op != "!=" {
		t.Fatalf("if cond = %#v, want != binary expr", stmt.Cond)
	}
}

func TestBuildVarDeclaration(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    var pid u32 = bpf.current_pid()
    return 0
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	stmt, ok := fn.Body[0].(VarDeclStmt)
	if !ok {
		t.Fatalf("body[0] = %T, want VarDeclStmt", fn.Body[0])
	}
	if stmt.Name != "pid" || stmt.Type.Name != "u32" {
		t.Fatalf("var decl = %#v, want pid u32", stmt)
	}
	call, ok := stmt.Value.(CallExpr)
	if !ok {
		t.Fatalf("var value = %T, want CallExpr", stmt.Value)
	}
	if sel, ok := call.Func.(SelectorExpr); !ok || sel.Field != "current_pid" {
		t.Fatalf("var call = %#v, want bpf.current_pid", call.Func)
	}
}

func TestBuildSwitchStatement(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@xdp
func F(ctx xdp.Context) i32 {
    verdict := xdp.Pass
    switch verdict {
    case xdp.Drop, xdp.Aborted:
        return xdp.Drop
    default:
        return xdp.Pass
    }
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	stmt, ok := fn.Body[1].(SwitchStmt)
	if !ok {
		t.Fatalf("body[1] = %T, want SwitchStmt", fn.Body[1])
	}
	if _, ok := stmt.Value.(IdentExpr); !ok {
		t.Fatalf("switch value = %T, want IdentExpr", stmt.Value)
	}
	if len(stmt.Cases) != 2 {
		t.Fatalf("cases = %d, want 2", len(stmt.Cases))
	}
	if stmt.Cases[0].Default || len(stmt.Cases[0].Values) != 2 {
		t.Fatalf("case[0] = %#v, want two explicit values", stmt.Cases[0])
	}
	if !stmt.Cases[1].Default || len(stmt.Cases[1].Body) != 1 {
		t.Fatalf("case[1] = %#v, want default with return", stmt.Cases[1])
	}
}

func TestBuildMapAttribute(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@max_entries(4096)
map Counts hash[u32, u32]
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	decl, ok := file.Decls[0].(MapDecl)
	if !ok {
		t.Fatalf("decl = %T, want MapDecl", file.Decls[0])
	}
	if decl.MaxEntries != "4096" {
		t.Fatalf("MaxEntries = %q, want 4096", decl.MaxEntries)
	}
	if len(decl.Attrs) != 1 || decl.Attrs[0].Name != "max_entries" {
		t.Fatalf("attrs = %#v, want @max_entries", decl.Attrs)
	}
	value, ok := decl.Attrs[0].Args[0].(IntExpr)
	if !ok || value.Value != "4096" {
		t.Fatalf("attr arg = %#v, want int 4096", decl.Attrs[0].Args)
	}
}

func TestBuildMapAttributeConstReference(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const CountEntries = 4096

@max_entries(CountEntries)
map Counts hash[u32, u32]
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 2 {
		t.Fatalf("decls = %d, want 2", len(file.Decls))
	}
	decl, ok := file.Decls[1].(MapDecl)
	if !ok {
		t.Fatalf("decl = %T, want MapDecl", file.Decls[1])
	}
	if decl.MaxEntries != "CountEntries" {
		t.Fatalf("MaxEntries = %q, want CountEntries", decl.MaxEntries)
	}
	value, ok := decl.Attrs[0].Args[0].(IdentExpr)
	if !ok || value.Name != "CountEntries" {
		t.Fatalf("attr arg = %#v, want ident CountEntries", decl.Attrs[0].Args)
	}
}

func TestBuildSignedIntegerConst(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const Negative i32 = -1
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	decl, ok := file.Decls[0].(ConstDecl)
	if !ok {
		t.Fatalf("decl = %T, want ConstDecl", file.Decls[0])
	}
	value, ok := decl.Value.(UnaryExpr)
	if !ok || value.Op != "-" {
		t.Fatalf("const value = %#v, want unary -", decl.Value)
	}
	if lit, ok := value.Expr.(IntExpr); !ok || lit.Value != "1" {
		t.Fatalf("unary operand = %#v, want int 1", value.Expr)
	}
}

func TestBuildPerCPUAndLRUMapKinds(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

map Counts percpu_hash[u32, u64]
map Slots percpu_array[u32, u64]
map Recent lru_hash[u32, u64]
map RecentByCPU lru_percpu_hash[u32, u64]
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 4 {
		t.Fatalf("decls = %#v, want four maps", file.Decls)
	}
	counts, ok := file.Decls[0].(MapDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want MapDecl", file.Decls[0])
	}
	if counts.Kind != MapKindPerCPUHash || counts.Key.Name != "u32" || counts.Val.Name != "u64" {
		t.Fatalf("counts = %#v, want percpu_hash[u32, u64]", counts)
	}
	slots, ok := file.Decls[1].(MapDecl)
	if !ok {
		t.Fatalf("decl[1] = %T, want MapDecl", file.Decls[1])
	}
	if slots.Kind != MapKindPerCPUArray || slots.Key.Name != "u32" || slots.Val.Name != "u64" {
		t.Fatalf("slots = %#v, want percpu_array[u32, u64]", slots)
	}
	recent, ok := file.Decls[2].(MapDecl)
	if !ok {
		t.Fatalf("decl[2] = %T, want MapDecl", file.Decls[2])
	}
	if recent.Kind != MapKindLRUHash || recent.Key.Name != "u32" || recent.Val.Name != "u64" {
		t.Fatalf("recent = %#v, want lru_hash[u32, u64]", recent)
	}
	recentByCPU, ok := file.Decls[3].(MapDecl)
	if !ok {
		t.Fatalf("decl[3] = %T, want MapDecl", file.Decls[3])
	}
	if recentByCPU.Kind != MapKindLRUPerCPU || recentByCPU.Key.Name != "u32" || recentByCPU.Val.Name != "u64" {
		t.Fatalf("recentByCPU = %#v, want lru_percpu_hash[u32, u64]", recentByCPU)
	}
}

func TestBuildBoolLiteralAST(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    enabled := true
    if !enabled || false {
        return 1
    }
    return 0
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	stmt, ok := fn.Body[0].(ShortVarStmt)
	if !ok {
		t.Fatalf("body[0] = %T, want ShortVarStmt", fn.Body[0])
	}
	lit, ok := stmt.Value.(BoolExpr)
	if !ok || !lit.Value {
		t.Fatalf("short var value = %#v, want true BoolExpr", stmt.Value)
	}
	branch, ok := fn.Body[1].(IfStmt)
	if !ok {
		t.Fatalf("body[1] = %T, want IfStmt", fn.Body[1])
	}
	cond, ok := branch.Cond.(BinaryExpr)
	if !ok || cond.Op != "||" {
		t.Fatalf("condition = %#v, want || binary expression", branch.Cond)
	}
	right, ok := cond.Right.(BoolExpr)
	if !ok || right.Value {
		t.Fatalf("right side = %#v, want false BoolExpr", cond.Right)
	}
}

func TestBuildIfElseAST(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if pid == 0 {
        return 0
    } else {
        return 1
    }
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[0].(FuncDecl)
	stmt, ok := fn.Body[1].(IfStmt)
	if !ok {
		t.Fatalf("body[1] = %T, want IfStmt", fn.Body[1])
	}
	if len(stmt.Then) != 1 || len(stmt.Else) != 1 {
		t.Fatalf("if branches = then %d else %d, want 1 and 1", len(stmt.Then), len(stmt.Else))
	}
	if _, ok := stmt.Else[0].(ReturnStmt); !ok {
		t.Fatalf("else[0] = %T, want ReturnStmt", stmt.Else[0])
	}
}

func TestBuildConstDeclaration(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const HTTPS u16 = 443
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	decl, ok := file.Decls[0].(ConstDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want ConstDecl", file.Decls[0])
	}
	value, ok := decl.Value.(IntExpr)
	if !ok {
		t.Fatalf("const value = %T, want IntExpr", decl.Value)
	}
	if decl.Name != "HTTPS" || decl.Type.Name != "u16" || value.Value != "443" {
		t.Fatalf("const decl = %#v value=%#v, want HTTPS u16 = 443", decl, value)
	}
}

func TestBuildConstGroupDeclaration(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const (
    HTTP u16 = 80
    HTTPS u16 = 443
)
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	group, ok := file.Decls[0].(ConstGroupDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want ConstGroupDecl", file.Decls[0])
	}
	if len(group.Consts) != 2 {
		t.Fatalf("consts = %#v, want two", group.Consts)
	}
	value, ok := group.Consts[1].Value.(IntExpr)
	if !ok {
		t.Fatalf("const value = %T, want IntExpr", group.Consts[1].Value)
	}
	if group.Consts[0].Name != "HTTP" || group.Consts[0].Type.Name != "u16" || group.Consts[1].Name != "HTTPS" || value.Value != "443" {
		t.Fatalf("const group = %#v value=%#v, want HTTP and HTTPS u16", group, value)
	}
}

func TestBuildEnumDeclaration(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

enum Verdict i32 {
    VerdictPass = 0
    VerdictDrop = 1
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(file.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(file.Decls))
	}
	decl, ok := file.Decls[0].(EnumDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want EnumDecl", file.Decls[0])
	}
	if decl.Name != "Verdict" || decl.Type.Name != "i32" || len(decl.Values) != 2 {
		t.Fatalf("enum decl = %#v, want Verdict i32 with two values", decl)
	}
	if decl.Values[0].Name != "VerdictPass" {
		t.Fatalf("enum values = %#v, want VerdictPass first", decl.Values)
	}
	value, ok := decl.Values[1].Value.(IntExpr)
	if !ok || value.Value != "1" {
		t.Fatalf("second enum value = %#v, want integer literal 1", decl.Values[1].Value)
	}
}

func TestBuildConstBeforeFunction(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const HTTPS = 443

@xdp
func F(ctx xdp.Context) i32 {
    return xdp.Pass
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if file.Package != "p" {
		t.Fatalf("package = %q, want p; tree: %s", file.Package, parsed.Tree.RootNode().SExpr(parsed.Lang))
	}
	if len(file.Decls) != 2 {
		t.Fatalf("decls = %d, want 2; tree: %s", len(file.Decls), parsed.Tree.RootNode().SExpr(parsed.Lang))
	}
}

func TestBuildStructLiteral(t *testing.T) {
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    Counts.update(pid, Count{seen: pid})
    return 0
}
`)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fn := file.Decls[2].(FuncDecl)
	stmt, ok := fn.Body[1].(ExprStmt)
	if !ok {
		t.Fatalf("body[1] = %T, want ExprStmt", fn.Body[1])
	}
	call := stmt.Expr.(CallExpr)
	lit, ok := call.Args[1].(StructLiteralExpr)
	if !ok {
		t.Fatalf("arg[1] = %T, want StructLiteralExpr", call.Args[1])
	}
	if lit.Type.Name != "Count" || len(lit.Fields) != 1 || lit.Fields[0].Name != "seen" {
		t.Fatalf("literal = %#v, want Count{seen: ...}", lit)
	}
}
