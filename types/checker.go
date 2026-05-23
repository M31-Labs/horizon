package types

import (
	"fmt"
	"slices"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
)

func Check(file ast.File) []diag.Diagnostic {
	env := NewEnv()
	var diags []diag.Diagnostic
	knownTypes := builtinTypes()
	structs := map[string]ast.TypeDecl{}
	maps := map[string]ast.MapDecl{}
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
			structs[typed.Name] = typed
		}
		if mapped, ok := decl.(ast.MapDecl); ok && mapped.Name != "" {
			maps[mapped.Name] = mapped
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
			diags = append(diags, validateFuncDecl(d, knownTypes, maps, structs)...)
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
		if decl.Kind == ast.MapKindArray && decl.Key.Name != "u32" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1204",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("array map %q must use u32 keys", decl.Name),
				Primary:  decl.Key.Span,
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

func validateFuncDecl(decl ast.FuncDecl, known map[string]bool, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl) []diag.Diagnostic {
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
	diags = append(diags, validateFuncBody(decl, maps, structs)...)
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

type valueType struct {
	Name     string
	Ref      ast.TypeRef
	Ptr      bool
	Resource bool
	MaybeNil bool
	Void     bool
}

func validateFuncBody(decl ast.FuncDecl, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl) []diag.Diagnostic {
	locals := map[string]valueType{}
	var diags []diag.Diagnostic
	for _, param := range decl.Params {
		if param.Name == "" {
			continue
		}
		locals[param.Name] = valueType{Name: param.Type.Name, Ref: param.Type, Ptr: param.Type.Ptr}
	}
	var checkStmt func(ast.Stmt)
	checkStmt = func(stmt ast.Stmt) {
		switch s := stmt.(type) {
		case ast.ShortVarStmt:
			typ, exprDiags := typeOfExpr(s.Value, locals, maps, structs)
			diags = append(diags, exprDiags...)
			if typ.Void {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1409",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("cannot assign void expression to %q", s.Name),
					Primary:  s.Span,
				})
				break
			}
			if s.Name != "" {
				locals[s.Name] = typ
			}
		case ast.AssignStmt:
			target, targetDiags := typeOfExpr(s.Target, locals, maps, structs)
			value, valueDiags := typeOfExpr(s.Value, locals, maps, structs)
			targetHadErrors := len(targetDiags) > 0
			diags = append(diags, targetDiags...)
			diags = append(diags, valueDiags...)
			if targetHadErrors {
				break
			}
			if target.Void {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1401",
					Severity: diag.SeverityError,
					Message:  "assignment target is not addressable",
					Primary:  s.Span,
				})
			} else if !assignable(target, value) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1402",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("cannot assign %s to %s", typeName(value), typeName(target)),
					Primary:  s.Span,
				})
			}
		case ast.ExprStmt:
			_, exprDiags := typeOfExpr(s.Expr, locals, maps, structs)
			diags = append(diags, exprDiags...)
		case ast.ReturnStmt:
			value, exprDiags := typeOfExpr(s.Value, locals, maps, structs)
			diags = append(diags, exprDiags...)
			if s.Value != nil && !assignable(valueType{Name: "i32"}, value) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1403",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("cannot return %s from i32 program", typeName(value)),
					Primary:  s.Span,
				})
			}
		case ast.IfStmt:
			_, exprDiags := typeOfExpr(s.Cond, locals, maps, structs)
			diags = append(diags, exprDiags...)
			for _, child := range s.Then {
				checkStmt(child)
			}
		case ast.ForStmt:
			if s.Init != nil {
				checkStmt(s.Init)
			}
			if s.Cond != nil {
				_, exprDiags := typeOfExpr(s.Cond, locals, maps, structs)
				diags = append(diags, exprDiags...)
			}
			if s.Post != nil {
				checkStmt(s.Post)
			}
			for _, child := range s.Body {
				checkStmt(child)
			}
		case ast.IncStmt:
			local, ok := locals[s.Name]
			if !ok {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1404",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("unknown identifier %q", s.Name),
					Primary:  s.Span,
				})
				break
			}
			if !isIntegerScalar(local.Name) && local.Name != "untyped_int" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1408",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s requires an integer variable, got %s", s.Op, typeName(local)),
					Primary:  s.Span,
				})
			}
		case ast.RawStmt:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1400",
				Severity: diag.SeverityError,
				Message:  "unsupported statement form",
				Primary:  s.Span,
				Suggest:  "use Horizon's Go-shaped statement subset instead of raw text",
			})
		}
	}
	for _, stmt := range decl.Body {
		checkStmt(stmt)
	}
	return diags
}

func typeOfExpr(expr ast.Expr, locals map[string]valueType, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl) (valueType, []diag.Diagnostic) {
	switch e := expr.(type) {
	case nil:
		return valueType{Void: true}, nil
	case ast.IdentExpr:
		if local, ok := locals[e.Name]; ok {
			return local, nil
		}
		if m, ok := maps[e.Name]; ok {
			return valueType{Name: string(m.Kind), Ref: m.Val}, nil
		}
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1404",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown identifier %q", e.Name),
			Primary:  e.Span,
		}}
	case ast.IntExpr:
		return valueType{Name: "untyped_int"}, nil
	case ast.NilExpr:
		return valueType{Name: "nil"}, nil
	case ast.SelectorExpr:
		if root, field, ok := selectorParts(e); ok && root == "bpf" {
			return valueType{Name: "helper:" + field}, nil
		}
		operand, diags := typeOfExpr(e.Operand, locals, maps, structs)
		if operand.Ptr {
			operand.Ptr = false
		}
		structDecl, ok := structs[operand.Name]
		if !ok {
			return valueType{Void: true}, append(diags, diag.Diagnostic{
				Code:     "HZN1405",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("%s has no fields", typeName(operand)),
				Primary:  e.Span,
			})
		}
		field, ok := findField(structDecl, e.Field)
		if !ok {
			return valueType{Void: true}, append(diags, diag.Diagnostic{
				Code:     "HZN1406",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("type %s has no field %q", structDecl.Name, e.Field),
				Primary:  e.Span,
			})
		}
		return valueType{Name: field.Type.Name, Ref: field.Type}, diags
	case ast.UnaryExpr:
		operand, diags := typeOfExpr(e.Expr, locals, maps, structs)
		switch e.Op {
		case "&":
			operand.Ptr = true
			return operand, diags
		default:
			return operand, diags
		}
	case ast.BinaryExpr:
		_, leftDiags := typeOfExpr(e.Left, locals, maps, structs)
		_, rightDiags := typeOfExpr(e.Right, locals, maps, structs)
		return valueType{Name: "bool"}, append(leftDiags, rightDiags...)
	case ast.CallExpr:
		return typeOfCall(e, locals, maps, structs)
	case ast.RawExpr:
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1407",
			Severity: diag.SeverityError,
			Message:  "unsupported expression form",
			Primary:  e.Span,
		}}
	default:
		return valueType{}, nil
	}
}

func typeOfCall(call ast.CallExpr, locals map[string]valueType, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl) (valueType, []diag.Diagnostic) {
	var diags []diag.Diagnostic
	root, method, ok := selectorParts(call.Func)
	if !ok {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1410",
			Severity: diag.SeverityError,
			Message:  "only compiler-known helper and map method calls are supported",
			Primary:  call.Span,
		}}
	}
	if root == "bpf" {
		return typeOfHelperCall(method, call, locals, maps, structs)
	}
	if m, ok := maps[root]; ok {
		switch method {
		case "lookup":
			if len(call.Args) != 1 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".lookup", 1, len(call.Args)))
				return valueType{Name: m.Val.Name, Ref: m.Val, Ptr: true, MaybeNil: true}, diags
			}
			if m.Kind != ast.MapKindHash && m.Kind != ast.MapKindArray {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1418",
					Severity: diag.SeverityError,
					Message:  "lookup is only valid on hash and array maps",
					Primary:  call.Span,
				})
			}
			arg, argDiags := typeOfExpr(call.Args[0], locals, maps, structs)
			diags = append(diags, argDiags...)
			if !assignable(valueType{Name: m.Key.Name, Ref: m.Key}, arg) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1419",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s.lookup expects key %s, got %s", root, typeName(valueType{Name: m.Key.Name, Ref: m.Key}), typeName(arg)),
					Primary:  call.Span,
				})
			}
			return valueType{Name: m.Val.Name, Ref: m.Val, Ptr: true, MaybeNil: true}, diags
		case "update":
			if len(call.Args) != 2 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".update", 2, len(call.Args)))
				return valueType{Name: "i64"}, diags
			}
			if m.Kind != ast.MapKindHash && m.Kind != ast.MapKindArray {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1420",
					Severity: diag.SeverityError,
					Message:  "update is only valid on hash and array maps",
					Primary:  call.Span,
				})
			}
			key, keyDiags := typeOfExpr(call.Args[0], locals, maps, structs)
			val, valDiags := typeOfExpr(call.Args[1], locals, maps, structs)
			diags = append(diags, keyDiags...)
			diags = append(diags, valDiags...)
			if !assignable(valueType{Name: m.Key.Name, Ref: m.Key}, key) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1421",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s.update expects key %s, got %s", root, typeName(valueType{Name: m.Key.Name, Ref: m.Key}), typeName(key)),
					Primary:  call.Span,
				})
			}
			if !assignable(valueType{Name: m.Val.Name, Ref: m.Val}, val) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1422",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s.update expects value %s, got %s", root, typeName(valueType{Name: m.Val.Name, Ref: m.Val}), typeName(val)),
					Primary:  call.Span,
				})
			}
			return valueType{Name: "i64"}, diags
		case "delete":
			if len(call.Args) != 1 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".delete", 1, len(call.Args)))
				return valueType{Name: "i64"}, diags
			}
			if m.Kind != ast.MapKindHash {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1423",
					Severity: diag.SeverityError,
					Message:  "delete is only valid on hash maps",
					Primary:  call.Span,
				})
			}
			key, keyDiags := typeOfExpr(call.Args[0], locals, maps, structs)
			diags = append(diags, keyDiags...)
			if !assignable(valueType{Name: m.Key.Name, Ref: m.Key}, key) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1424",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s.delete expects key %s, got %s", root, typeName(valueType{Name: m.Key.Name, Ref: m.Key}), typeName(key)),
					Primary:  call.Span,
				})
			}
			return valueType{Name: "i64"}, diags
		case "reserve":
			if len(call.Args) != 0 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".reserve", 0, len(call.Args)))
			}
			if m.Kind != ast.MapKindRingbuf {
				diags = append(diags, diag.Diagnostic{Code: "HZN1411", Severity: diag.SeverityError, Message: "reserve is only valid on ringbuf maps", Primary: call.Span})
			}
			return valueType{Name: m.Val.Name, Ref: m.Val, Ptr: true, Resource: true, MaybeNil: true}, diags
		case "submit", "discard":
			if len(call.Args) != 1 {
				diags = append(diags, argCountDiagnostic(call.Span, root+"."+method, 1, len(call.Args)))
				return valueType{Void: true}, diags
			}
			arg, argDiags := typeOfExpr(call.Args[0], locals, maps, structs)
			diags = append(diags, argDiags...)
			if !arg.Resource || arg.Name != m.Val.Name {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1412",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("%s.%s expects a reserved *%s", root, method, m.Val.Name),
					Primary:  call.Span,
				})
			}
			return valueType{Void: true}, diags
		default:
			return valueType{}, []diag.Diagnostic{{
				Code:     "HZN1413",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("map %q has no method %q", root, method),
				Primary:  call.Span,
			}}
		}
	}
	return valueType{}, []diag.Diagnostic{{
		Code:     "HZN1414",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("unknown call target %q", root),
		Primary:  call.Span,
	}}
}

func typeOfHelperCall(name string, call ast.CallExpr, locals map[string]valueType, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl) (valueType, []diag.Diagnostic) {
	switch name {
	case "current_pid", "current_ppid", "current_uid":
		if len(call.Args) != 0 {
			return valueType{Name: "u32"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf."+name, 0, len(call.Args))}
		}
		return valueType{Name: "u32"}, nil
	case "current_comm":
		if len(call.Args) != 1 {
			return valueType{Void: true}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf.current_comm", 1, len(call.Args))}
		}
		arg, diags := typeOfExpr(call.Args[0], locals, maps, structs)
		if !arg.Ptr || arg.Ref.Len != "16" || arg.Ref.Elem == nil || arg.Ref.Elem.Name != "u8" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1415",
				Severity: diag.SeverityError,
				Message:  "bpf.current_comm expects a pointer to [16]u8",
				Primary:  call.Span,
			})
		}
		return valueType{Void: true}, diags
	default:
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1416",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown kernel helper bpf.%s", name),
			Primary:  call.Span,
		}}
	}
}

func selectorParts(expr ast.Expr) (string, string, bool) {
	sel, ok := expr.(ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	root, ok := sel.Operand.(ast.IdentExpr)
	if !ok {
		return "", "", false
	}
	return root.Name, sel.Field, true
}

func findField(structDecl ast.TypeDecl, name string) (ast.Field, bool) {
	for _, field := range structDecl.Fields {
		if field.Name == name {
			return field, true
		}
	}
	return ast.Field{}, false
}

func assignable(dst, src valueType) bool {
	if src.Name == "untyped_int" {
		return isScalar(dst.Name)
	}
	if src.Name == "nil" {
		return dst.Ptr || dst.MaybeNil
	}
	if dst.Ptr != src.Ptr {
		return false
	}
	if dst.Ref.Len != "" || src.Ref.Len != "" {
		return dst.Ref.Len == src.Ref.Len && dst.Ref.Elem != nil && src.Ref.Elem != nil && dst.Ref.Elem.Name == src.Ref.Elem.Name
	}
	return dst.Name == src.Name
}

func isScalar(name string) bool {
	switch name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool":
		return true
	default:
		return false
	}
}

func isIntegerScalar(name string) bool {
	switch name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64":
		return true
	default:
		return false
	}
}

func typeName(t valueType) string {
	if t.Void {
		return "void"
	}
	name := t.Name
	if name == "" && t.Ref.Name != "" {
		name = t.Ref.Name
	}
	if name == "untyped_int" {
		return "integer literal"
	}
	if t.Ref.Len != "" && t.Ref.Elem != nil {
		name = "[" + t.Ref.Len + "]" + t.Ref.Elem.Name
	}
	if t.Ptr {
		return "*" + name
	}
	return name
}

func argCountDiagnostic(primary span.Span, name string, want, got int) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN1417",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("%s expects %d argument(s), got %d", name, want, got),
		Primary:  primary,
	}
}
