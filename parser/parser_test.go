package parser

import "testing"

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
		"raw_statement",
	} {
		if firstNamedDescendant(file.Tree.RootNode(), file.Lang, typ) == nil {
			t.Fatalf("tree missing %s in %s", typ, file.Tree.RootNode().SExpr(file.Lang))
		}
	}
}
