package types

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func TestCheckFunctionParametersAreInScope(t *testing.T) {
	file := ast.File{
		Package: "probes",
		Decls: []ast.Decl{
			ast.FuncDecl{
				Name: "OnExec",
				Attrs: []ast.Attr{{
					Name: "tracepoint",
					Args: []ast.Expr{ast.StringExpr{Value: "sched:sched_process_exec"}},
				}},
				Params: []ast.Param{{
					Name: "ctx",
					Type: ast.TypeRef{Name: "tracepoint.Exec"},
				}},
				Return: ast.TypeRef{Name: "i32"},
				Body: []ast.Stmt{
					ast.ShortVarStmt{Name: "seen", Value: ast.IdentExpr{Name: "ctx"}},
					ast.ReturnStmt{Value: ast.IntExpr{Value: "0"}},
				},
			},
		},
	}
	diags := Check(file)
	if slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1404" }) {
		t.Fatalf("diagnostics = %#v, want function parameter in scope", diags)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want no errors", diags)
	}
}
