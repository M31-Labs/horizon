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
