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
	if len(typeDecl.Fields) != 4 {
		t.Fatalf("fields = %d, want 4", len(typeDecl.Fields))
	}
	comm := typeDecl.Fields[3]
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
	if len(fn.Body) != 8 {
		t.Fatalf("body statements = %d, want 8", len(fn.Body))
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
	if _, ok := fn.Body[5].(ExprStmt); !ok {
		t.Fatalf("body[5] = %T, want ExprStmt", fn.Body[5])
	}
	if _, ok := fn.Body[6].(ExprStmt); !ok {
		t.Fatalf("body[6] = %T, want ExprStmt", fn.Body[6])
	}
	if _, ok := fn.Body[7].(ReturnStmt); !ok {
		t.Fatalf("body[7] = %T, want ReturnStmt", fn.Body[7])
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
