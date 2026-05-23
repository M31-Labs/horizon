package types

import (
	"fmt"
	"slices"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func Check(file ast.File) []diag.Diagnostic {
	env := NewEnv()
	var diags []diag.Diagnostic
	knownTypes := builtinTypes()
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
		if typed, ok := decl.(ast.TypeDecl); ok && typed.Name != "" {
			knownTypes[typed.Name] = true
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			for _, field := range d.Fields {
				diags = append(diags, validateTypeRef(field.Type, knownTypes)...)
			}
		case ast.MapDecl:
			diags = append(diags, validateMapDecl(d, knownTypes)...)
		case ast.FuncDecl:
			diags = append(diags, validateFuncDecl(d, knownTypes)...)
		case ast.ConstDecl:
			if d.Value == nil {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1101",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("const %q is missing a value", d.Name),
					Primary:  d.Span,
				})
			}
		}
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

func builtinTypes() map[string]bool {
	return map[string]bool{
		"u8": true, "u16": true, "u32": true, "u64": true,
		"i8": true, "i16": true, "i32": true, "i64": true,
		"bool":            true,
		"tracepoint.Exec": true,
	}
}

func validateMapDecl(decl ast.MapDecl, known map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	switch decl.Kind {
	case ast.MapKindRingbuf:
		if decl.Val.IsZero() {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1201",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("ringbuf map %q requires a value type", decl.Name),
				Primary:  decl.Span,
			})
		}
		diags = append(diags, validateTypeRef(decl.Val, known)...)
	case ast.MapKindHash, ast.MapKindArray:
		if decl.Key.IsZero() || decl.Val.IsZero() {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1202",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("%s map %q requires key and value types", decl.Kind, decl.Name),
				Primary:  decl.Span,
			})
		}
		diags = append(diags, validateTypeRef(decl.Key, known)...)
		diags = append(diags, validateTypeRef(decl.Val, known)...)
	default:
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1203",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unsupported map kind %q", decl.Kind),
			Primary:  decl.Span,
			Suggest:  "v0 supports ringbuf[T], hash[K, V], and array[K, V]",
		})
	}
	return diags
}

func validateFuncDecl(decl ast.FuncDecl, known map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	if !hasAttr(decl.Attrs, "tracepoint") {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1301",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q is missing a tracepoint section", decl.Name),
			Primary:  decl.Span,
			Suggest:  `add @tracepoint("category:event") above the function`,
		})
	}
	for _, attr := range decl.Attrs {
		switch attr.Name {
		case "tracepoint", "capability":
			if len(attr.Args) != 1 {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1302",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("@%s requires one string argument", attr.Name),
					Primary:  attr.Span,
				})
			}
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1303",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("unsupported attribute @%s", attr.Name),
				Primary:  attr.Span,
			})
		}
	}
	for _, param := range decl.Params {
		diags = append(diags, validateTypeRef(param.Type, known)...)
	}
	if decl.Return.IsZero() {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1304",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q must return i32", decl.Name),
			Primary:  decl.Span,
		})
	} else if decl.Return.Name != "i32" {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1305",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q returns %s; eBPF programs must return i32 in v0", decl.Name, decl.Return.Name),
			Primary:  decl.Return.Span,
		})
	}
	return diags
}

func validateTypeRef(ref ast.TypeRef, known map[string]bool) []diag.Diagnostic {
	if ref.IsZero() {
		return nil
	}
	if ref.Elem != nil {
		return validateTypeRef(*ref.Elem, known)
	}
	var diags []diag.Diagnostic
	for _, arg := range ref.Args {
		diags = append(diags, validateTypeRef(arg, known)...)
	}
	if ref.Name == "" || len(ref.Args) > 0 {
		return diags
	}
	if known[ref.Name] {
		return diags
	}
	return append(diags, diag.Diagnostic{
		Code:     "HZN1102",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("unknown type %q", ref.Name),
		Primary:  ref.Span,
	})
}

func hasAttr(attrs []ast.Attr, name string) bool {
	return slices.ContainsFunc(attrs, func(attr ast.Attr) bool {
		return attr.Name == name
	})
}
