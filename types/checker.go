package types

import (
	"fmt"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func Check(file ast.File) []diag.Diagnostic {
	env := NewEnv()
	var diags []diag.Diagnostic
	if file.Package == "" {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1001",
			Severity: diag.SeverityError,
			Message:  "missing package declaration",
			Primary:  file.Span,
		})
	}
	for _, decl := range file.Decls {
		name := declName(decl)
		if name == "" {
			continue
		}
		if prev, ok := env.Decl(name); ok {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1002",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("duplicate declaration %q", name),
				Primary:  decl.GetSpan(),
				Notes:    []string{fmt.Sprintf("previous declaration at line %d", prev.GetSpan().Start.Line)},
			})
			continue
		}
		env.Add(name, decl)
	}
	return diags
}

func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case ast.TypeDecl:
		return d.Name
	case ast.MapDecl:
		return d.Name
	case ast.FuncDecl:
		return d.Name
	case ast.ConstDecl:
		return d.Name
	default:
		return ""
	}
}
