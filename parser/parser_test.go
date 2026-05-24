package parser

import (
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

func TestParseExecwatchPackage(t *testing.T) {
	file, err := ParsePath("../examples/execwatch/exec.hzn")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if file.Package != "probes" {
		t.Fatalf("package = %q, want probes", file.Package)
	}
	for _, typ := range []string{
		"type_declaration",
		"map_declaration",
		"function_declaration",
		"attribute",
		"statement",
	} {
		if firstNamedDescendant(file.Tree.RootNode(), file.Lang, typ) == nil {
			t.Fatalf("tree missing %s in %s", typ, file.Tree.RootNode().SExpr(file.Lang))
		}
	}
}

func TestParseStatements(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    event.pid = bpf.current_pid()
    bpf.current_comm(&event.comm)
    Events.submit(event)
    return 0
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "statement") != 4 {
		t.Fatalf("statement count = %d, want 4", countNamedDescendants(file.Tree.RootNode(), file.Lang, "statement"))
	}
}

func TestParseIfThenAssignments(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }

    event.pid = bpf.current_pid()
    Events.submit(event)
    return 0
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "statement") != 6 {
		t.Fatalf("statement count = %d, want 6", countNamedDescendants(file.Tree.RootNode(), file.Lang, "statement"))
	}
}

func TestParseSingleLineBlockStatement(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    if event == nil { return 0 }
    return 0
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "return_statement") != 2 {
		t.Fatalf("return statement count = %d, want 2", countNamedDescendants(file.Tree.RootNode(), file.Lang, "return_statement"))
	}
}

func TestParseElseAndElseIf(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if pid == 0 {
        return 0
    } else if pid == 1 {
        return 1
    } else {
        return 2
    }
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "if_statement") != 2 {
		t.Fatalf("if statement count = %d, want 2; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "if_statement"), file.Tree.RootNode().SExpr(file.Lang))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "return_statement") != 3 {
		t.Fatalf("return statement count = %d, want 3; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "return_statement"), file.Tree.RootNode().SExpr(file.Lang))
	}
}

func TestParseBoundedForClause(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@tracepoint("sched:sched_process_exec")
func F(ctx tracepoint.Exec) i32 {
    for i := 0; i < 4; i++ {
        bpf.current_pid()
    }
    return 0
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "for_statement") != 1 {
		t.Fatalf("for statement count = %d, want 1", countNamedDescendants(file.Tree.RootNode(), file.Lang, "for_statement"))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "increment_statement") != 1 {
		t.Fatalf("increment statement count = %d, want 1", countNamedDescendants(file.Tree.RootNode(), file.Lang, "increment_statement"))
	}
}

func TestParseConstBeforeFunction(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const HTTPS = 443

@xdp
func F(ctx xdp.Context) i32 {
    return xdp.Pass
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if file.Package != "p" {
		t.Fatalf("package = %q, want p; tree: %s", file.Package, file.Tree.RootNode().SExpr(file.Lang))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "const_declaration") != 1 {
		t.Fatalf("const count = %d, want 1; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "const_declaration"), file.Tree.RootNode().SExpr(file.Lang))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "function_declaration") != 1 {
		t.Fatalf("function count = %d, want 1; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "function_declaration"), file.Tree.RootNode().SExpr(file.Lang))
	}
}

func TestParseTypedOperators(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

const Mask = 0x0f

@xdp
func F(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    if (xdp.ntohs(tcp.dst_port) == 443) && ((tcp.data_off & Mask) != 0) {
        return xdp.Drop
    }
    return xdp.Pass
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "binary_expression") < 4 {
		t.Fatalf("binary expression count = %d, want at least 4; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "binary_expression"), file.Tree.RootNode().SExpr(file.Lang))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "parenthesized_expression") < 3 {
		t.Fatalf("parenthesized expression count = %d, want at least 3; tree: %s", countNamedDescendants(file.Tree.RootNode(), file.Lang, "parenthesized_expression"), file.Tree.RootNode().SExpr(file.Lang))
	}
}

func TestParseStructLiteral(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

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
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "struct_literal") != 1 {
		t.Fatalf("struct literal count = %d, want 1", countNamedDescendants(file.Tree.RootNode(), file.Lang, "struct_literal"))
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "literal_field") != 1 {
		t.Fatalf("literal field count = %d, want 1", countNamedDescendants(file.Tree.RootNode(), file.Lang, "literal_field"))
	}
}

func TestParseBareAttribute(t *testing.T) {
	src := SourceFile{Path: "inline.hzn", Bytes: []byte(`package p

@xdp
func DropAll(ctx xdp.Context) i32 {
    return xdp.Drop
}
`)}
	file, err := ParseSource(src)
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	if countNamedDescendants(file.Tree.RootNode(), file.Lang, "attribute") != 1 {
		t.Fatalf("attribute count = %d, want 1", countNamedDescendants(file.Tree.RootNode(), file.Lang, "attribute"))
	}
}

func countNamedDescendants(n *gotreesitter.Node, lang *gotreesitter.Language, typ string) int {
	if n == nil {
		return 0
	}
	count := 0
	if n.IsNamed() && n.Type(lang) == typ {
		count++
	}
	for i := 0; i < n.NamedChildCount(); i++ {
		count += countNamedDescendants(n.NamedChild(i), lang, typ)
	}
	return count
}
