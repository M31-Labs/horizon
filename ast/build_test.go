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
