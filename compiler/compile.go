package compiler

import (
	"errors"
	"fmt"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
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
	fileIndexes := make([]int, 0, len(paths))
	hadFrontEndError := false
	for _, path := range paths {
		parsed, err := parser.ParsePath(path)
		if err != nil {
			hadFrontEndError = true
			d := frontEndDiagnostic(path, err)
			result.Files = append(result.Files, FileResult{
				Path:        path,
				Diagnostics: []diag.Diagnostic{d},
			})
			result.Diagnostics = append(result.Diagnostics, d)
			continue
		}
		file, err := ast.Build(parsed)
		if err != nil {
			hadFrontEndError = true
			d := frontEndDiagnostic(path, err)
			result.Files = append(result.Files, FileResult{
				Path:        path,
				Package:     parsed.Package,
				Diagnostics: []diag.Diagnostic{d},
			})
			result.Diagnostics = append(result.Diagnostics, d)
			continue
		}
		fileIndexes = append(fileIndexes, len(result.Files))
		files = append(files, *file)
		result.Files = append(result.Files, FileResult{
			Path:    path,
			Package: file.Package,
		})
	}
	if hadFrontEndError {
		return &result, nil
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
		result.Files[fileIndexes[i]].Diagnostics = diags
		result.Diagnostics = append(result.Diagnostics, diags...)
	}
	resolveMapMaxEntries(files)
	program, lowerDiags := ir.FromAST(mergeASTFiles(files, packageName))
	result.Program = program
	result.Diagnostics = append(result.Diagnostics, lowerDiags...)
	if !diag.HasErrors(result.Diagnostics) {
		result.Diagnostics = append(result.Diagnostics, validate.Program(result.Program)...)
	}
	if !diag.HasErrors(result.Diagnostics) {
		if err := bindgen.Validate(result.Program, "bindings"); err != nil {
			if d, ok := bindgen.DiagnosticForError(err); ok {
				result.Diagnostics = append(result.Diagnostics, d)
			} else {
				return nil, err
			}
		}
	}
	return &result, nil
}

func resolveMapMaxEntries(files []ast.File) {
	consts := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.ConstDecl:
				value, ok := d.Value.(ast.IntExpr)
				if ok {
					consts[d.Name] = value.Value
				}
			case ast.ConstGroupDecl:
				for _, constant := range d.Consts {
					value, ok := constant.Value.(ast.IntExpr)
					if ok {
						consts[constant.Name] = value.Value
					}
				}
			case ast.EnumDecl:
				for _, enumValue := range d.Values {
					value, ok := enumValue.Value.(ast.IntExpr)
					if ok {
						consts[enumValue.Name] = value.Value
					}
				}
			}
		}
	}
	if len(consts) == 0 {
		return
	}
	for i := range files {
		for j, decl := range files[i].Decls {
			m, ok := decl.(ast.MapDecl)
			if !ok {
				continue
			}
			if resolved, ok := consts[m.MaxEntries]; ok {
				m.MaxEntries = resolved
				files[i].Decls[j] = m
			}
		}
	}
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

func frontEndDiagnostic(path string, err error) diag.Diagnostic {
	var parseErr *parser.ParseError
	if errors.As(err, &parseErr) {
		return diag.Diagnostic{
			Code:     "HZN0100",
			Severity: diag.SeverityError,
			Message:  parseErr.Message,
			Primary:  parseErr.Span(),
			Suggest:  "fix the Horizon syntax before typechecking or C emission can continue",
		}
	}
	return diag.Diagnostic{
		Code:     "HZN0200",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("could not build Horizon AST: %v", err),
		Primary:  span.Span{File: span.FileID(path)},
	}
}
