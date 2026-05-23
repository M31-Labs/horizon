package compiler

import (
	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/parser"
	htypes "m31labs.dev/horizon/types"
)

type FileResult struct {
	Path        string
	Package     string
	Diagnostics []diag.Diagnostic
}

type Result struct {
	Files       []FileResult
	Diagnostics []diag.Diagnostic
}

func CheckPath(root string) (*Result, error) {
	paths, err := CollectFiles(root)
	if err != nil {
		return nil, err
	}
	var result Result
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
		result.Files = append(result.Files, FileResult{
			Path:        path,
			Package:     file.Package,
			Diagnostics: diags,
		})
		result.Diagnostics = append(result.Diagnostics, diags...)
	}
	return &result, nil
}
