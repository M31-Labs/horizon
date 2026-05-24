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
	packageName := ""
	files := make([]ast.File, 0, len(paths))
	for _, path := range paths {
		parsed, err := parser.ParsePath(path)
		if err != nil {
			return nil, err
		}
		file, err := ast.Build(parsed)
		if err != nil {
			return nil, err
		}
		files = append(files, *file)
		result.Files = append(result.Files, FileResult{
			Path:    path,
			Package: file.Package,
		})
	}
	typeDiags := htypes.CheckPackage(files)
	for i, file := range files {
		diags := append([]diag.Diagnostic{}, typeDiags[i]...)
		if file.Package != "" {
			if packageName == "" {
				packageName = file.Package
			} else if file.Package != packageName {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1003",
					Severity: diag.SeverityError,
					Message:  "all files in a Horizon package must use the same package declaration",
					Primary:  file.Span,
				})
			}
		}
		result.Files[i].Diagnostics = diags
		result.Diagnostics = append(result.Diagnostics, diags...)
	}
	program, lowerDiags := ir.FromAST(mergeASTFiles(files, packageName))
	result.Program = program
	result.Diagnostics = append(result.Diagnostics, lowerDiags...)
	if !diag.HasErrors(result.Diagnostics) {
		result.Diagnostics = append(result.Diagnostics, validate.Program(result.Program)...)
	}
	return &result, nil
}

func mergeASTFiles(files []ast.File, packageName string) ast.File {
	var merged ast.File
	merged.Package = packageName
	if len(files) > 0 {
		merged.Span = files[0].Span
	}
	for _, file := range files {
		merged.Imports = append(merged.Imports, file.Imports...)
		merged.Decls = append(merged.Decls, file.Decls...)
	}
	return merged
}
