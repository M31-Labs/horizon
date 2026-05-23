package compiler

import (
	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/parser"
	htypes "m31labs.dev/horizon/types"
	"m31labs.dev/horizon/validate"
)

type FileResult struct {
	Path        string
	Package     string
	Diagnostics []diag.Diagnostic
}

type Result struct {
	Files       []FileResult
	Program     ir.Program
	Diagnostics []diag.Diagnostic
}

func CheckPath(root string) (*Result, error) {
	return AnalyzePath(root)
}

func AnalyzePath(root string) (*Result, error) {
	paths, err := CollectFiles(root)
	if err != nil {
		return nil, err
	}
	var result Result
	var programs []ir.Program
	packageName := ""
	for _, path := range paths {
		parsed, err := parser.ParsePath(path)
		if err != nil {
			return nil, err
		}
		file, err := ast.Build(parsed)
		if err != nil {
			return nil, err
		}
		diags := htypes.Check(*file)
		if packageName == "" {
			packageName = file.Package
		} else if file.Package != "" && file.Package != packageName {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1003",
				Severity: diag.SeverityError,
				Message:  "all files in a Horizon package must use the same package declaration",
				Primary:  file.Span,
			})
		}
		program, lowerDiags := ir.FromAST(*file)
		diags = append(diags, lowerDiags...)
		programs = append(programs, program)
		result.Files = append(result.Files, FileResult{
			Path:        path,
			Package:     file.Package,
			Diagnostics: diags,
		})
		result.Diagnostics = append(result.Diagnostics, diags...)
	}
	result.Program = ir.Merge(programs...)
	result.Diagnostics = append(result.Diagnostics, validate.Program(result.Program)...)
	return &result, nil
}
