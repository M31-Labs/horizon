package types

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
)

func Check(file ast.File) []diag.Diagnostic {
	diags := CheckPackage([]ast.File{file})
	if len(diags) == 0 {
		return nil
	}
	return diags[0]
}

func CheckPackage(files []ast.File) [][]diag.Diagnostic {
	diags := make([][]diag.Diagnostic, len(files))
	index := newPackageDeclIndex()
	env := NewEnv()
	for i, file := range files {
		collectPackageFileDecls(file, &index, env, &diags[i])
	}
	files = resolveTypeAliasesInFiles(files, index.typeAliases)
	resolved := indexResolvedDecls(files)
	callGraphDiags := validateFunctionCallGraph(resolved.funcs)
	for i, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case ast.TypeDecl:
				diags[i] = append(diags[i], validateTypeDecl(d, index.knownTypes, resolved.structs, resolved.userStructs, index.typeAliases)...)
			case ast.TypeGroupDecl:
				diags[i] = append(diags[i], validateTypeGroupDecl(d, index.knownTypes, resolved.structs, resolved.userStructs, index.typeAliases)...)
			case ast.MapDecl:
				diags[i] = append(diags[i], validateMapDecl(d, index.knownTypes, resolved.userStructs, resolved.consts)...)
			case ast.FuncDecl:
				diags[i] = append(diags[i], validateFuncDecl(d, index.knownTypes, resolved.maps, resolved.structs, resolved.userStructs, resolved.consts, resolved.funcs, resolved.capabilities)...)
				diags[i] = append(diags[i], callGraphDiags[d.Name]...)
			case ast.ConstDecl:
				diags[i] = append(diags[i], validateConstDecl(d, index.knownTypes)...)
			case ast.ConstGroupDecl:
				diags[i] = append(diags[i], validateConstGroupDecl(d, index.knownTypes)...)
			case ast.EnumDecl:
				diags[i] = append(diags[i], validateEnumDecl(d, index.knownTypes)...)
			case ast.CapabilityDecl:
				diags[i] = append(diags[i], validateCapabilityDecl(d)...)
			}
		}
	}
	return diags
}

type packageDeclIndex struct {
	knownTypes  map[string]bool
	typeAliases map[string]ast.TypeRef
}

func newPackageDeclIndex() packageDeclIndex {
	return packageDeclIndex{
		knownTypes:  builtinTypes(),
		typeAliases: map[string]ast.TypeRef{},
	}
}

func collectPackageFileDecls(file ast.File, index *packageDeclIndex, env *Env, diags *[]diag.Diagnostic) {
	if file.Package == "" {
		*diags = append(*diags, diag.Diagnostic{
			Code:     "HZN1001",
			Severity: diag.SeverityError,
			Message:  "missing package declaration",
			Primary:  file.Span,
		})
	}
	for _, decl := range file.Decls {
		collectPackageDecl(decl, index, env, diags)
	}
}

func collectPackageDecl(decl ast.Decl, index *packageDeclIndex, env *Env, diags *[]diag.Diagnostic) {
	name := declName(decl)
	if name != "" && !declarePackageName(diags, env, name, decl) {
		return
	}
	switch d := decl.(type) {
	case ast.TypeDecl:
		collectTypeDecl(d, index)
	case ast.TypeGroupDecl:
		collectTypeGroupDecl(d, index, env, diags)
	case ast.EnumDecl:
		collectEnumDecl(d, env, diags)
	case ast.ConstGroupDecl:
		collectConstGroupDecl(d, env, diags)
	}
}

func collectTypeDecl(decl ast.TypeDecl, index *packageDeclIndex) {
	if decl.Name == "" {
		return
	}
	index.knownTypes[decl.Name] = true
	if decl.IsAlias() {
		index.typeAliases[decl.Name] = decl.Alias
	}
}

func collectTypeGroupDecl(decl ast.TypeGroupDecl, index *packageDeclIndex, env *Env, diags *[]diag.Diagnostic) {
	for _, typ := range decl.Types {
		if typ.Name == "" || !declarePackageName(diags, env, typ.Name, typ) {
			continue
		}
		collectTypeDecl(typ, index)
	}
}

func collectEnumDecl(decl ast.EnumDecl, env *Env, diags *[]diag.Diagnostic) {
	for _, value := range decl.Values {
		if value.Name == "" || !declarePackageName(diags, env, value.Name, value) {
			continue
		}
	}
}

func collectConstGroupDecl(decl ast.ConstGroupDecl, env *Env, diags *[]diag.Diagnostic) {
	for _, constant := range decl.Consts {
		if constant.Name == "" || !declarePackageName(diags, env, constant.Name, constant) {
			continue
		}
	}
}

func declarePackageName(diags *[]diag.Diagnostic, env *Env, name string, decl DeclRef) bool {
	if compilerNamespace(name) {
		*diags = append(*diags, diag.Diagnostic{
			Code:     "HZN1004",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("declaration %q conflicts with a compiler namespace", name),
			Primary:  decl.GetSpan(),
			Suggest:  "compiler namespaces such as bpf, xdp, tc, cgroup, lsm, kprobe, kretprobe, and tracepoint are reserved",
		})
		return false
	}
	if prev, ok := env.Decl(name); ok {
		*diags = append(*diags, diag.Diagnostic{
			Code:     "HZN1002",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("duplicate declaration %q", name),
			Primary:  decl.GetSpan(),
			Notes:    []string{fmt.Sprintf("previous declaration at line %d", prev.GetSpan().Start.Line)},
		})
		return false
	}
	env.Add(name, decl)
	return true
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
	case ast.EnumDecl:
		return d.Name
	case ast.CapabilityDecl:
		return d.Name
	default:
		return ""
	}
}

func enumValueConst(enum ast.EnumDecl, value ast.EnumValue) ast.ConstDecl {
	return ast.ConstDecl{
		Name:  value.Name,
		Type:  enum.Type,
		Value: value.Value,
		Span:  value.Span,
	}
}

type resolvedDeclIndex struct {
	structs      map[string]ast.TypeDecl
	maps         map[string]ast.MapDecl
	consts       map[string]ast.ConstDecl
	capabilities map[string]ast.CapabilityDecl
	userStructs  map[string]ast.TypeDecl
	funcs        map[string]ast.FuncDecl
}

func indexResolvedDecls(files []ast.File) resolvedDeclIndex {
	index := resolvedDeclIndex{
		structs:      builtinStructs(),
		maps:         map[string]ast.MapDecl{},
		consts:       map[string]ast.ConstDecl{},
		capabilities: map[string]ast.CapabilityDecl{},
		userStructs:  map[string]ast.TypeDecl{},
		funcs:        map[string]ast.FuncDecl{},
	}
	for _, file := range files {
		for _, decl := range file.Decls {
			indexResolvedDecl(&index, decl)
		}
	}
	return index
}

func indexResolvedDecl(index *resolvedDeclIndex, decl ast.Decl) {
	switch d := decl.(type) {
	case ast.TypeDecl:
		if !d.IsAlias() && d.Name != "" {
			index.structs[d.Name] = d
			index.userStructs[d.Name] = d
		}
	case ast.TypeGroupDecl:
		indexResolvedTypeGroup(index, d)
	case ast.MapDecl:
		if d.Name != "" {
			index.maps[d.Name] = d
		}
	case ast.ConstDecl:
		if d.Name != "" {
			index.consts[d.Name] = d
		}
	case ast.ConstGroupDecl:
		indexResolvedConstGroup(index, d)
	case ast.EnumDecl:
		indexResolvedEnum(index, d)
	case ast.CapabilityDecl:
		if d.Name != "" {
			index.capabilities[d.Name] = d
		}
	case ast.FuncDecl:
		if d.Name != "" {
			index.funcs[d.Name] = d
		}
	}
}

func indexResolvedTypeGroup(index *resolvedDeclIndex, decl ast.TypeGroupDecl) {
	for _, typ := range decl.Types {
		if !typ.IsAlias() && typ.Name != "" {
			index.structs[typ.Name] = typ
			index.userStructs[typ.Name] = typ
		}
	}
}

func indexResolvedConstGroup(index *resolvedDeclIndex, decl ast.ConstGroupDecl) {
	for _, constant := range decl.Consts {
		if constant.Name != "" {
			index.consts[constant.Name] = constant
		}
	}
}

func indexResolvedEnum(index *resolvedDeclIndex, decl ast.EnumDecl) {
	for _, value := range decl.Values {
		if value.Name != "" {
			index.consts[value.Name] = enumValueConst(decl, value)
		}
	}
}

func resolveTypeAliasesInFiles(files []ast.File, aliases map[string]ast.TypeRef) []ast.File {
	if len(aliases) == 0 {
		return files
	}
	out := make([]ast.File, len(files))
	for i, file := range files {
		out[i] = resolveTypeAliasesInFile(file, aliases)
	}
	return out
}

func resolveTypeAliasesInFile(file ast.File, aliases map[string]ast.TypeRef) ast.File {
	for i, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			if d.IsAlias() {
				file.Decls[i] = d
				continue
			}
			for j := range d.Fields {
				d.Fields[j].Type = resolveTypeAliasRef(d.Fields[j].Type, aliases, map[string]bool{})
			}
			file.Decls[i] = d
		case ast.TypeGroupDecl:
			for j := range d.Types {
				if d.Types[j].IsAlias() {
					continue
				}
				for k := range d.Types[j].Fields {
					d.Types[j].Fields[k].Type = resolveTypeAliasRef(d.Types[j].Fields[k].Type, aliases, map[string]bool{})
				}
			}
			file.Decls[i] = d
		case ast.MapDecl:
			d.Key = resolveTypeAliasRef(d.Key, aliases, map[string]bool{})
			d.Val = resolveTypeAliasRef(d.Val, aliases, map[string]bool{})
			file.Decls[i] = d
		case ast.ConstDecl:
			d.Type = resolveTypeAliasRef(d.Type, aliases, map[string]bool{})
			file.Decls[i] = d
		case ast.ConstGroupDecl:
			for j := range d.Consts {
				d.Consts[j].Type = resolveTypeAliasRef(d.Consts[j].Type, aliases, map[string]bool{})
			}
			file.Decls[i] = d
		case ast.EnumDecl:
			d.Type = resolveTypeAliasRef(d.Type, aliases, map[string]bool{})
			file.Decls[i] = d
		case ast.FuncDecl:
			for j := range d.Params {
				d.Params[j].Type = resolveTypeAliasRef(d.Params[j].Type, aliases, map[string]bool{})
			}
			d.Return = resolveTypeAliasRef(d.Return, aliases, map[string]bool{})
			d.Body = resolveTypeAliasesInStmts(d.Body, aliases)
			file.Decls[i] = d
		}
	}
	return file
}

func resolveTypeAliasesInStmts(stmts []ast.Stmt, aliases map[string]ast.TypeRef) []ast.Stmt {
	if len(stmts) == 0 {
		return stmts
	}
	out := make([]ast.Stmt, len(stmts))
	for i, stmt := range stmts {
		out[i] = resolveTypeAliasesInStmt(stmt, aliases)
	}
	return out
}

func resolveTypeAliasesInStmt(stmt ast.Stmt, aliases map[string]ast.TypeRef) ast.Stmt {
	switch s := stmt.(type) {
	case ast.VarDeclStmt:
		s.Type = resolveTypeAliasRef(s.Type, aliases, map[string]bool{})
		return s
	case ast.IfStmt:
		s.Init = resolveTypeAliasesInStmt(s.Init, aliases)
		s.Then = resolveTypeAliasesInStmts(s.Then, aliases)
		s.Else = resolveTypeAliasesInStmts(s.Else, aliases)
		return s
	case ast.ForStmt:
		s.Init = resolveTypeAliasesInStmt(s.Init, aliases)
		s.Post = resolveTypeAliasesInStmt(s.Post, aliases)
		s.Body = resolveTypeAliasesInStmts(s.Body, aliases)
		return s
	case ast.SwitchStmt:
		for j := range s.Cases {
			s.Cases[j].Body = resolveTypeAliasesInStmts(s.Cases[j].Body, aliases)
		}
		return s
	default:
		return stmt
	}
}

func resolveTypeAliasRef(ref ast.TypeRef, aliases map[string]ast.TypeRef, visiting map[string]bool) ast.TypeRef {
	if ref.IsZero() {
		return ref
	}
	for i := range ref.Args {
		ref.Args[i] = resolveTypeAliasRef(ref.Args[i], aliases, visiting)
	}
	if ref.Elem != nil {
		elem := resolveTypeAliasRef(*ref.Elem, aliases, visiting)
		ref.Elem = &elem
	}
	if ref.Name == "" || visiting[ref.Name] {
		return ref
	}
	alias, ok := aliases[ref.Name]
	if !ok {
		return ref
	}
	visiting[ref.Name] = true
	resolved := resolveTypeAliasRef(alias, aliases, visiting)
	delete(visiting, ref.Name)
	resolved.Span = ref.Span
	return resolved
}

func builtinTypes() map[string]bool {
	return map[string]bool{
		"u8": true, "u16": true, "u32": true, "u64": true,
		"i8": true, "i16": true, "i32": true, "i64": true,
		"bool":              true,
		"tracepoint.Exec":   true,
		"xdp.Context":       true,
		"xdp.Eth":           true,
		"xdp.IPv4":          true,
		"xdp.TCP":           true,
		"xdp.UDP":           true,
		"tc.Context":        true,
		"cgroup.Connect":    true,
		"lsm.Context":       true,
		"kprobe.Context":    true,
		"kretprobe.Context": true,
	}
}

func builtinStructs() map[string]ast.TypeDecl {
	return map[string]ast.TypeDecl{
		"xdp.Eth": {
			Name: "xdp.Eth",
			Fields: []ast.Field{
				{Name: "dst", Type: fixedArrayType("u8", "6")},
				{Name: "src", Type: fixedArrayType("u8", "6")},
				{Name: "proto", Type: ast.TypeRef{Name: "u16"}},
			},
		},
		"xdp.IPv4": {
			Name: "xdp.IPv4",
			Fields: []ast.Field{
				{Name: "version_ihl", Type: ast.TypeRef{Name: "u8"}},
				{Name: "tos", Type: ast.TypeRef{Name: "u8"}},
				{Name: "total_len", Type: ast.TypeRef{Name: "u16"}},
				{Name: "id", Type: ast.TypeRef{Name: "u16"}},
				{Name: "frag_off", Type: ast.TypeRef{Name: "u16"}},
				{Name: "ttl", Type: ast.TypeRef{Name: "u8"}},
				{Name: "protocol", Type: ast.TypeRef{Name: "u8"}},
				{Name: "check", Type: ast.TypeRef{Name: "u16"}},
				{Name: "src", Type: ast.TypeRef{Name: "u32"}},
				{Name: "dst", Type: ast.TypeRef{Name: "u32"}},
			},
		},
		"xdp.TCP": {
			Name: "xdp.TCP",
			Fields: []ast.Field{
				{Name: "src_port", Type: ast.TypeRef{Name: "u16"}},
				{Name: "dst_port", Type: ast.TypeRef{Name: "u16"}},
				{Name: "seq", Type: ast.TypeRef{Name: "u32"}},
				{Name: "ack", Type: ast.TypeRef{Name: "u32"}},
				{Name: "data_off", Type: ast.TypeRef{Name: "u8"}},
				{Name: "flags", Type: ast.TypeRef{Name: "u8"}},
				{Name: "window", Type: ast.TypeRef{Name: "u16"}},
				{Name: "check", Type: ast.TypeRef{Name: "u16"}},
				{Name: "urg_ptr", Type: ast.TypeRef{Name: "u16"}},
			},
		},
		"xdp.UDP": {
			Name: "xdp.UDP",
			Fields: []ast.Field{
				{Name: "src_port", Type: ast.TypeRef{Name: "u16"}},
				{Name: "dst_port", Type: ast.TypeRef{Name: "u16"}},
				{Name: "len", Type: ast.TypeRef{Name: "u16"}},
				{Name: "check", Type: ast.TypeRef{Name: "u16"}},
			},
		},
	}
}

func fixedArrayType(elem string, len string) ast.TypeRef {
	return ast.TypeRef{Len: len, Elem: &ast.TypeRef{Name: elem}}
}

func validateMapDecl(decl ast.MapDecl, known map[string]bool, userStructs map[string]ast.TypeDecl, consts map[string]ast.ConstDecl) []diag.Diagnostic {
	var diags []diag.Diagnostic
	diags = append(diags, validateMapAttrs(decl, consts)...)
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
		if !decl.Val.IsZero() && ringbufValueNeedsStructDiagnostic(decl.Val, known, userStructs) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1209",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("ringbuf map %q must use a declared struct value type", decl.Name),
				Primary:  decl.Val.Span,
				Suggest:  "declare an event record such as `type Event struct { ... }` and use `ringbuf[Event]`",
			})
		}
	case ast.MapKindHash, ast.MapKindArray, ast.MapKindPerCPUHash, ast.MapKindPerCPUArray, ast.MapKindLRUHash, ast.MapKindLRUPerCPU:
		if decl.Key.IsZero() || decl.Val.IsZero() {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1202",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("%s map %q requires key and value types", decl.Kind, decl.Name),
				Primary:  decl.Span,
			})
		}
		if decl.Kind.IsArrayLike() && decl.Key.Name != "u32" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1204",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("%s map %q must use u32 keys", decl.Kind, decl.Name),
				Primary:  decl.Key.Span,
			})
		}
		diags = append(diags, validateTypeRef(decl.Key, known)...)
		diags = append(diags, validateTypeRef(decl.Val, known)...)
		diags = append(diags, validateStoredTypeRef(decl.Key, known, userStructs, fmt.Sprintf("map %s key", decl.Name))...)
		diags = append(diags, validateStoredTypeRef(decl.Val, known, userStructs, fmt.Sprintf("map %s value", decl.Name))...)
	default:
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1203",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unsupported map kind %q", decl.Kind),
			Primary:  decl.Span,
			Suggest:  "v0 supports ringbuf[T], hash[K, V], array[K, V], percpu_hash[K, V], percpu_array[K, V], lru_hash[K, V], and lru_percpu_hash[K, V]",
		})
	}
	return diags
}

func validateStoredTypeRef(ref ast.TypeRef, known map[string]bool, userStructs map[string]ast.TypeDecl, label string) []diag.Diagnostic {
	if ref.IsZero() || ref.Ptr {
		return nil
	}
	var diags []diag.Diagnostic
	if ref.Elem != nil {
		diags = append(diags, validateStoredTypeRef(*ref.Elem, known, userStructs, label)...)
	}
	for _, arg := range ref.Args {
		diags = append(diags, validateStoredTypeRef(arg, known, userStructs, label)...)
	}
	if ref.Name == "" || !known[ref.Name] || isScalar(ref.Name) {
		return diags
	}
	if _, ok := userStructs[ref.Name]; ok {
		return diags
	}
	diags = append(diags, diag.Diagnostic{
		Code:     "HZN1110",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("%s stores compiler-owned type %s", label, ref.Name),
		Primary:  ref.Span,
		Suggest:  "store scalar fields or declared Horizon structs; use compiler-owned context and packet header types only through helper calls",
	})
	return diags
}

func ringbufValueNeedsStructDiagnostic(ref ast.TypeRef, known map[string]bool, userStructs map[string]ast.TypeDecl) bool {
	if ref.Name == "" {
		return true
	}
	if _, ok := userStructs[ref.Name]; ok {
		return false
	}
	return known[ref.Name]
}

func validateMapAttrs(decl ast.MapDecl, consts map[string]ast.ConstDecl) []diag.Diagnostic {
	var diags []diag.Diagnostic
	seenMaxEntries := false
	for _, attr := range decl.Attrs {
		switch attr.Name {
		case "max_entries":
			if seenMaxEntries {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1208",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("map %q declares @max_entries more than once", decl.Name),
					Primary:  attr.Span,
				})
				continue
			}
			seenMaxEntries = true
			value, ok := mapMaxEntriesValue(attr, consts)
			if !ok {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1206",
					Severity: diag.SeverityError,
					Message:  "@max_entries requires one positive integer literal or integer const",
					Primary:  attr.Span,
					Suggest:  "write `@max_entries(4096)` or `@max_entries(MapEntries)` above the map declaration",
				})
				continue
			}
			if decl.Kind == ast.MapKindRingbuf && !isPowerOfTwo(value) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1207",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("ringbuf map %q @max_entries must be a power of two", decl.Name),
					Primary:  attr.Span,
					Suggest:  "use a power-of-two byte size such as 262144",
				})
			}
		default:
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1205",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("unsupported map attribute @%s", attr.Name),
				Primary:  attr.Span,
				Suggest:  "Horizon maps support @max_entries(...)",
			})
		}
	}
	return diags
}

func validateTypeDecl(decl ast.TypeDecl, known map[string]bool, structs map[string]ast.TypeDecl, userStructs map[string]ast.TypeDecl, aliases map[string]ast.TypeRef) []diag.Diagnostic {
	if decl.IsAlias() {
		return validateTypeAliasDecl(decl, known, aliases)
	}
	var diags []diag.Diagnostic
	seenFields := map[string]span.Span{}
	for _, field := range decl.Fields {
		diags = append(diags, validateTypeRef(field.Type, known)...)
		fieldLabel := fmt.Sprintf("field %s.%s", decl.Name, field.Name)
		if field.Name == "" {
			fieldLabel = "field in struct " + decl.Name
		}
		diags = append(diags, validateStoredTypeRef(field.Type, known, userStructs, fieldLabel)...)
		if field.Name != "" {
			if previous, ok := seenFields[field.Name]; ok {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1107",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("duplicate field %q in struct %s", field.Name, decl.Name),
					Primary:  field.Span,
					Notes:    []string{fmt.Sprintf("previous field at line %d", previous.Start.Line)},
				})
			} else {
				seenFields[field.Name] = field.Span
			}
		}
		if typeRefContainsStruct(decl.Name, field.Type, structs, map[string]bool{}) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1108",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("struct %s recursively contains itself through field %q", decl.Name, field.Name),
				Primary:  field.Span,
				Suggest:  "Horizon structs are finite by-value records; keep recursive relationships in keyed maps instead of embedding the same record type",
			})
		}
	}
	return diags
}

func validateTypeGroupDecl(decl ast.TypeGroupDecl, known map[string]bool, structs map[string]ast.TypeDecl, userStructs map[string]ast.TypeDecl, aliases map[string]ast.TypeRef) []diag.Diagnostic {
	if len(decl.Types) == 0 {
		return []diag.Diagnostic{{
			Code:     "HZN1113",
			Severity: diag.SeverityError,
			Message:  "type group must declare at least one type",
			Primary:  decl.Span,
			Suggest:  "write `type Name struct { ... }` or add one or more aliases or structs inside the group",
		}}
	}
	var diags []diag.Diagnostic
	for _, typ := range decl.Types {
		diags = append(diags, validateTypeDecl(typ, known, structs, userStructs, aliases)...)
	}
	return diags
}

func validateTypeAliasDecl(decl ast.TypeDecl, known map[string]bool, aliases map[string]ast.TypeRef) []diag.Diagnostic {
	var diags []diag.Diagnostic
	diags = append(diags, validateTypeRef(decl.Alias, known)...)
	if aliasHasCycle(decl.Name, aliases, map[string]bool{}) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1111",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("type alias %s recursively references itself", decl.Name),
			Primary:  decl.Span,
			Suggest:  "type aliases must resolve to a scalar or bool type",
		})
		return diags
	}
	resolved := resolveTypeAliasRef(decl.Alias, aliases, map[string]bool{})
	if !resolvedTypeAliasTarget(resolved) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1112",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("type alias %s must target a scalar or bool type", decl.Name),
			Primary:  decl.Alias.Span,
			Suggest:  "use aliases for domain scalar names such as `type Port = u16`; use `type Event struct { ... }` for records",
		})
	}
	return diags
}

func aliasHasCycle(name string, aliases map[string]ast.TypeRef, visiting map[string]bool) bool {
	if name == "" {
		return false
	}
	if visiting[name] {
		return true
	}
	next, ok := aliases[name]
	if !ok || next.Name == "" {
		return false
	}
	visiting[name] = true
	defer delete(visiting, name)
	return aliasHasCycle(next.Name, aliases, visiting)
}

func resolvedTypeAliasTarget(ref ast.TypeRef) bool {
	return !ref.Ptr && ref.Elem == nil && len(ref.Args) == 0 && isScalar(ref.Name)
}

func typeRefContainsStruct(target string, ref ast.TypeRef, structs map[string]ast.TypeDecl, visiting map[string]bool) bool {
	if ref.IsZero() || target == "" {
		return false
	}
	if ref.Ptr {
		return false
	}
	if ref.Elem != nil && typeRefContainsStruct(target, *ref.Elem, structs, visiting) {
		return true
	}
	for _, arg := range ref.Args {
		if typeRefContainsStruct(target, arg, structs, visiting) {
			return true
		}
	}
	if ref.Name == "" {
		return false
	}
	if ref.Name == target {
		return true
	}
	decl, ok := structs[ref.Name]
	if !ok || visiting[ref.Name] {
		return false
	}
	visiting[ref.Name] = true
	defer delete(visiting, ref.Name)
	for _, field := range decl.Fields {
		if typeRefContainsStruct(target, field.Type, structs, visiting) {
			return true
		}
	}
	return false
}

func mapMaxEntriesValue(attr ast.Attr, consts map[string]ast.ConstDecl) (uint64, bool) {
	if len(attr.Args) != 1 {
		return 0, false
	}
	switch value := attr.Args[0].(type) {
	case ast.IntExpr:
		return parseMapMaxEntriesLiteral(value.Value)
	case ast.IdentExpr:
		constant, ok := consts[value.Name]
		if !ok {
			return 0, false
		}
		lit, ok := constant.Value.(ast.IntExpr)
		if !ok {
			return 0, false
		}
		return parseMapMaxEntriesLiteral(lit.Value)
	default:
		return 0, false
	}
}

func parseMapMaxEntriesLiteral(lit string) (uint64, bool) {
	parsed, err := strconv.ParseUint(lit, 0, 32)
	if err != nil || parsed == 0 {
		return 0, false
	}
	return parsed, true
}

func isPowerOfTwo(value uint64) bool {
	return value != 0 && value&(value-1) == 0
}

func validateConstDecl(decl ast.ConstDecl, known map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	constTypeValid := true
	if !decl.Type.IsZero() {
		diags = append(diags, validateTypeRef(decl.Type, known)...)
		if decl.Type.Ptr || decl.Type.Elem != nil || len(decl.Type.Args) > 0 || !isScalar(decl.Type.Name) {
			constTypeValid = false
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1104",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("const %q must use a scalar integer or bool type in Horizon v0", decl.Name),
				Primary:  decl.Type.Span,
				Suggest:  "use an explicit scalar type such as `u32`, `u64`, or `bool`",
			})
		}
	}
	if decl.Value == nil {
		return append(diags, diag.Diagnostic{
			Code:     "HZN1101",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("const %q is missing a value", decl.Name),
			Primary:  decl.Span,
		})
	}
	value, ok := constValueType(decl.Value)
	if !ok {
		return append(diags, diag.Diagnostic{
			Code:     "HZN1103",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("const %q must be an integer or bool literal in Horizon v0", decl.Name),
			Primary:  decl.Value.GetSpan(),
			Suggest:  "keep constants simple and explicit, for example `const Port = 443` or `const Enabled = true`",
		})
	}
	if !decl.Type.IsZero() && constTypeValid {
		target := valueType{Name: decl.Type.Name, Ref: decl.Type, Ptr: decl.Type.Ptr}
		if d, ok := assignabilityDiagnostic(
			"HZN1105",
			fmt.Sprintf("cannot assign %s to const %q of type %s", typeName(value), decl.Name, typeName(target)),
			target,
			value,
			decl.Value.GetSpan(),
		); ok {
			diags = append(diags, d)
		}
	}
	return diags
}

func validateConstGroupDecl(decl ast.ConstGroupDecl, known map[string]bool) []diag.Diagnostic {
	if len(decl.Consts) == 0 {
		return []diag.Diagnostic{{
			Code:     "HZN1109",
			Severity: diag.SeverityError,
			Message:  "const group must declare at least one constant",
			Primary:  decl.Span,
			Suggest:  "write `const Name u32 = 1` or add one or more constants inside the group",
		}}
	}
	var diags []diag.Diagnostic
	for _, constant := range decl.Consts {
		diags = append(diags, validateConstDecl(constant, known)...)
	}
	return diags
}

func validateEnumDecl(decl ast.EnumDecl, known map[string]bool) []diag.Diagnostic {
	var diags []diag.Diagnostic
	diags = append(diags, validateTypeRef(decl.Type, known)...)
	enumTypeValid := !decl.Type.IsZero() && !decl.Type.Ptr && decl.Type.Elem == nil && len(decl.Type.Args) == 0 && isIntegerScalar(decl.Type.Name)
	if !enumTypeValid {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1120",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("enum %q must use a scalar integer backing type", decl.Name),
			Primary:  decl.Type.Span,
			Suggest:  "use an explicit integer type such as u8, u16, u32, u64, i32, or i64",
		})
	}
	if len(decl.Values) == 0 {
		return append(diags, diag.Diagnostic{
			Code:     "HZN1121",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("enum %q must declare at least one value", decl.Name),
			Primary:  decl.Span,
		})
	}
	for _, value := range decl.Values {
		if value.Value == nil {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1122",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("enum value %q is missing a value", value.Name),
				Primary:  value.Span,
			})
			continue
		}
		typ, ok := constValueType(value.Value)
		if !ok || typ.Name == "bool" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1122",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("enum value %q must be an integer literal", value.Name),
				Primary:  value.Value.GetSpan(),
				Suggest:  "enum values are explicit integer constants; write a literal such as 0, 1, or -1",
			})
			continue
		}
		if enumTypeValid {
			target := valueType{Name: decl.Type.Name, Ref: decl.Type}
			if d, ok := assignabilityDiagnostic(
				"HZN1123",
				fmt.Sprintf("cannot assign %s to enum value %q of type %s", typeName(typ), value.Name, typeName(target)),
				target,
				typ,
				value.Value.GetSpan(),
			); ok {
				diags = append(diags, d)
			}
		}
	}
	return diags
}

func constValueType(expr ast.Expr) (valueType, bool) {
	switch e := expr.(type) {
	case ast.IntExpr:
		return valueType{Name: "untyped_int", IntLiteral: e.Value}, true
	case ast.BoolExpr:
		return valueType{Name: "bool"}, true
	case ast.UnaryExpr:
		if e.Op != "-" {
			return valueType{}, false
		}
		operand, ok := constValueType(e.Expr)
		if !ok || operand.Name != "untyped_int" || operand.IntLiteral == "" {
			return valueType{}, false
		}
		operand.IntLiteral = negateIntegerLiteral(operand.IntLiteral)
		operand.NonZero = literalNonZero(operand.IntLiteral)
		operand.NonNegative = literalNonNegative(operand.IntLiteral)
		return operand, true
	default:
		return valueType{}, false
	}
}

func constDeclType(decl ast.ConstDecl) (valueType, bool) {
	if !decl.Type.IsZero() && !decl.Type.Ptr && decl.Type.Elem == nil && len(decl.Type.Args) == 0 && isScalar(decl.Type.Name) {
		typ := valueType{Name: decl.Type.Name, Ref: decl.Type}
		if value, ok := constValueType(decl.Value); ok && value.IntLiteral != "" && isIntegerScalar(decl.Type.Name) {
			typ.IntLiteral = value.IntLiteral
			typ.NonZero = literalNonZero(value.IntLiteral)
			typ.NonNegative = literalNonNegative(value.IntLiteral)
		}
		return typ, true
	}
	typ, ok := constValueType(decl.Value)
	if ok && typ.IntLiteral != "" {
		typ.NonZero = literalNonZero(typ.IntLiteral)
		typ.NonNegative = literalNonNegative(typ.IntLiteral)
	}
	return typ, ok
}

func validateFuncDecl(decl ast.FuncDecl, known map[string]bool, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl, userStructs map[string]ast.TypeDecl, consts map[string]ast.ConstDecl, funcs map[string]ast.FuncDecl, capabilities map[string]ast.CapabilityDecl) []diag.Diagnostic {
	var diags []diag.Diagnostic
	sections := sectionAttrs(decl.Attrs)
	isHelper := len(sections) == 0
	if len(sections) > 1 {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1306",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q has multiple eBPF program sections", decl.Name),
			Primary:  decl.Span,
			Suggest:  `use exactly one section attribute such as @tracepoint(...), @xdp, @tc("ingress"), @cgroup("connect4"), @lsm("file_open"), @kprobe(...), or @kretprobe(...)`,
		})
	}
	for _, attr := range decl.Attrs {
		switch attr.Name {
		case "tracepoint":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1302",
					Severity: diag.SeverityError,
					Message:  "@tracepoint requires one string argument",
					Primary:  attr.Span,
				})
			}
		case "xdp":
			if len(attr.Args) != 0 {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1309",
					Severity: diag.SeverityError,
					Message:  "@xdp does not take arguments; choose the interface at attach time",
					Primary:  attr.Span,
				})
			}
		case "tc":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1312",
					Severity: diag.SeverityError,
					Message:  `@tc requires one direction string argument, "ingress" or "egress"`,
					Primary:  attr.Span,
				})
				break
			}
			direction := attrStringArg(attr)
			if direction != "ingress" && direction != "egress" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1313",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("@tc direction %q is not supported", direction),
					Primary:  attr.Span,
					Suggest:  `use @tc("ingress") or @tc("egress")`,
				})
			}
		case "cgroup":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1314",
					Severity: diag.SeverityError,
					Message:  `@cgroup requires one attach string argument, "connect4" or "connect6"`,
					Primary:  attr.Span,
				})
				break
			}
			attach := attrStringArg(attr)
			if attach != "connect4" && attach != "connect6" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1315",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("@cgroup attach %q is not supported in Horizon v0", attach),
					Primary:  attr.Span,
					Suggest:  `use @cgroup("connect4") or @cgroup("connect6")`,
				})
			}
		case "lsm":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1316",
					Severity: diag.SeverityError,
					Message:  "@lsm requires one kernel LSM hook string argument",
					Primary:  attr.Span,
				})
				break
			}
			if attrStringArg(attr) == "" {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1317",
					Severity: diag.SeverityError,
					Message:  "@lsm hook cannot be empty",
					Primary:  attr.Span,
					Suggest:  `use an explicit hook such as @lsm("file_open")`,
				})
			}
		case "kprobe":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1310",
					Severity: diag.SeverityError,
					Message:  "@kprobe requires one kernel symbol string argument",
					Primary:  attr.Span,
				})
			}
		case "kretprobe":
			if !attrHasStringArg(attr) {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1311",
					Severity: diag.SeverityError,
					Message:  "@kretprobe requires one kernel symbol string argument",
					Primary:  attr.Span,
				})
			}
		case "capability":
			diags = append(diags, validateCapabilityAttr(attr, capabilities)...)
			if isHelper {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1318",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("helper function %q cannot declare a capability", decl.Name),
					Primary:  attr.Span,
					Suggest:  "capabilities belong on eBPF entrypoint functions with an explicit section attribute",
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
	if len(sections) == 1 {
		diags = append(diags, validateSectionSignature(decl, sections[0])...)
	}
	for _, param := range decl.Params {
		diags = append(diags, validateTypeRef(param.Type, known)...)
	}
	diags = append(diags, validateTypeRef(decl.Return, known)...)
	if isHelper {
		diags = append(diags, validateHelperSignature(decl)...)
	} else {
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
	}
	diags = append(diags, validateFuncBody(decl, known, maps, structs, userStructs, consts, sections, funcs)...)
	return diags
}

func validateCapabilityDecl(decl ast.CapabilityDecl) []diag.Diagnostic {
	if decl.Value != "" {
		return nil
	}
	return []diag.Diagnostic{{
		Code:     "HZN1322",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("capability alias %q must name a capability", decl.Name),
		Primary:  decl.Span,
		Suggest:  `use a stable capability string such as "kernel.process.exec.observe"`,
	}}
}

func validateCapabilityAttr(attr ast.Attr, capabilities map[string]ast.CapabilityDecl) []diag.Diagnostic {
	if len(attr.Args) != 1 {
		return []diag.Diagnostic{{
			Code:     "HZN1302",
			Severity: diag.SeverityError,
			Message:  "@capability requires one string argument or capability alias",
			Primary:  attr.Span,
		}}
	}
	switch value := attr.Args[0].(type) {
	case ast.StringExpr:
		if value.Value == "" {
			return []diag.Diagnostic{{
				Code:     "HZN1322",
				Severity: diag.SeverityError,
				Message:  "@capability string cannot be empty",
				Primary:  value.Span,
				Suggest:  `use a stable capability string such as "kernel.process.exec.observe"`,
			}}
		}
		return nil
	case ast.IdentExpr:
		if _, ok := capabilities[value.Name]; ok {
			return nil
		}
		return []diag.Diagnostic{{
			Code:     "HZN1321",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown capability alias %q", value.Name),
			Primary:  value.Span,
			Suggest:  fmt.Sprintf("declare it with capability %s = \"...\" or use a string literal", value.Name),
		}}
	default:
		return []diag.Diagnostic{{
			Code:     "HZN1302",
			Severity: diag.SeverityError,
			Message:  "@capability requires one string argument or capability alias",
			Primary:  attr.Span,
		}}
	}
}

func validateHelperSignature(decl ast.FuncDecl) []diag.Diagnostic {
	var diags []diag.Diagnostic
	for _, param := range decl.Params {
		if !helperScalarType(param.Type) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1319",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("helper function %q parameter %q must be a scalar or bool value", decl.Name, param.Name),
				Primary:  param.Type.Span,
				Suggest:  "keep reusable helpers scalar-only in v0; pass resources through compiler-known helpers inside an eBPF entrypoint",
			})
		}
	}
	if decl.Return.IsZero() {
		return append(diags, diag.Diagnostic{
			Code:     "HZN1320",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("helper function %q must return a scalar or bool value", decl.Name),
			Primary:  decl.Span,
			Suggest:  "return an explicit scalar value such as i32, u32, u64, or bool",
		})
	}
	if !helperScalarType(decl.Return) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1320",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("helper function %q return type must be scalar or bool, got %s", decl.Name, decl.Return.Name),
			Primary:  decl.Return.Span,
			Suggest:  "Horizon v0 user helpers are inline scalar helpers; keep resources and records local to entrypoints",
		})
	}
	return diags
}

func helperScalarType(ref ast.TypeRef) bool {
	return !ref.IsZero() && !ref.Ptr && ref.Elem == nil && len(ref.Args) == 0 && isScalar(ref.Name)
}

func validateFunctionCallGraph(funcs map[string]ast.FuncDecl) map[string][]diag.Diagnostic {
	graph := map[string][]string{}
	for name, fn := range funcs {
		if len(sectionAttrs(fn.Attrs)) != 0 {
			continue
		}
		for _, called := range calledFunctionNames(fn.Body, funcs) {
			calledFn := funcs[called]
			if len(sectionAttrs(calledFn.Attrs)) == 0 {
				graph[name] = append(graph[name], called)
			}
		}
	}
	out := map[string][]diag.Diagnostic{}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	reported := map[string]bool{}
	var visit func(string) bool
	visit = func(name string) bool {
		if visiting[name] {
			if !reported[name] {
				fn := funcs[name]
				out[name] = append(out[name], diag.Diagnostic{
					Code:     "HZN1503",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("helper function %q participates in a recursive call cycle", name),
					Primary:  fn.Span,
					Suggest:  "Horizon helper functions must be acyclic so clang can inline them predictably for the verifier",
				})
				reported[name] = true
			}
			return true
		}
		if visited[name] {
			return false
		}
		visiting[name] = true
		cyclic := false
		for _, called := range graph[name] {
			if visit(called) {
				cyclic = true
			}
		}
		delete(visiting, name)
		visited[name] = true
		return cyclic
	}
	for name := range graph {
		visit(name)
	}
	return out
}

func calledFunctionNames(stmts []ast.Stmt, funcs map[string]ast.FuncDecl) []string {
	seen := map[string]bool{}
	var out []string
	var walkStmt func(ast.Stmt)
	var walkExpr func(ast.Expr)
	walkStmt = func(stmt ast.Stmt) {
		switch s := stmt.(type) {
		case nil:
			return
		case ast.ShortVarStmt:
			walkExpr(s.Value)
		case ast.VarDeclStmt:
			walkExpr(s.Value)
		case ast.AssignStmt:
			walkExpr(s.Target)
			walkExpr(s.Value)
		case ast.ExprStmt:
			walkExpr(s.Expr)
		case ast.ReturnStmt:
			walkExpr(s.Value)
		case ast.IfStmt:
			walkStmt(s.Init)
			walkExpr(s.Cond)
			for _, child := range s.Then {
				walkStmt(child)
			}
			for _, child := range s.Else {
				walkStmt(child)
			}
		case ast.ForStmt:
			walkStmt(s.Init)
			walkExpr(s.Cond)
			walkStmt(s.Post)
			for _, child := range s.Body {
				walkStmt(child)
			}
		case ast.SwitchStmt:
			walkExpr(s.Value)
			for _, c := range s.Cases {
				for _, value := range c.Values {
					walkExpr(value)
				}
				for _, child := range c.Body {
					walkStmt(child)
				}
			}
		}
	}
	walkExpr = func(expr ast.Expr) {
		switch e := expr.(type) {
		case nil:
			return
		case ast.CallExpr:
			if name, ok := identCallTarget(e.Func); ok {
				if _, found := funcs[name]; found && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
			walkExpr(e.Func)
			for _, arg := range e.Args {
				walkExpr(arg)
			}
		case ast.SelectorExpr:
			walkExpr(e.Operand)
		case ast.UnaryExpr:
			walkExpr(e.Expr)
		case ast.BinaryExpr:
			walkExpr(e.Left)
			walkExpr(e.Right)
		case ast.StructLiteralExpr:
			for _, field := range e.Fields {
				walkExpr(field.Value)
			}
		}
	}
	for _, stmt := range stmts {
		walkStmt(stmt)
	}
	return out
}

func validateTypeRef(ref ast.TypeRef, known map[string]bool) []diag.Diagnostic {
	if ref.IsZero() {
		return nil
	}
	var diags []diag.Diagnostic
	if ref.Ptr {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1106",
			Severity: diag.SeverityError,
			Message:  "source-authored pointer types are not supported in Horizon v0",
			Primary:  ref.Span,
			Suggest:  "use compiler-known nullable resources from map lookup, ringbuf reserve, packet helpers, or fixed-array helper operands instead of writing *T types",
		})
	}
	if ref.Elem != nil {
		diags = append(diags, validateTypeRef(*ref.Elem, known)...)
		if ref.Len != "" || ref.Ptr {
			return diags
		}
	}
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

type sectionSpec struct {
	Attr    ast.Attr
	Context string
}

func sectionAttrs(attrs []ast.Attr) []sectionSpec {
	var out []sectionSpec
	for _, attr := range attrs {
		switch attr.Name {
		case "tracepoint":
			out = append(out, sectionSpec{Attr: attr, Context: "tracepoint.Exec"})
		case "xdp":
			out = append(out, sectionSpec{Attr: attr, Context: "xdp.Context"})
		case "tc":
			out = append(out, sectionSpec{Attr: attr, Context: "tc.Context"})
		case "cgroup":
			out = append(out, sectionSpec{Attr: attr, Context: "cgroup.Connect"})
		case "lsm":
			out = append(out, sectionSpec{Attr: attr, Context: "lsm.Context"})
		case "kprobe":
			out = append(out, sectionSpec{Attr: attr, Context: "kprobe.Context"})
		case "kretprobe":
			out = append(out, sectionSpec{Attr: attr, Context: "kretprobe.Context"})
		}
	}
	return out
}

func validateSectionSignature(decl ast.FuncDecl, section sectionSpec) []diag.Diagnostic {
	if len(decl.Params) != 1 {
		return []diag.Diagnostic{{
			Code:     "HZN1307",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("@%s program %q must accept exactly one context parameter", section.Attr.Name, decl.Name),
			Primary:  decl.Span,
			Suggest:  fmt.Sprintf("use `func %s(ctx %s) i32`", decl.Name, section.Context),
		}}
	}
	if decl.Params[0].Type.Name != section.Context {
		return []diag.Diagnostic{{
			Code:     "HZN1308",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("@%s program %q must use context type %s", section.Attr.Name, decl.Name, section.Context),
			Primary:  decl.Params[0].Type.Span,
			Suggest:  fmt.Sprintf("change the context parameter to `%s %s`", decl.Params[0].Name, section.Context),
		}}
	}
	return nil
}

type valueType struct {
	Name         string
	Ref          ast.TypeRef
	Ptr          bool
	Resource     bool
	MaybeNil     bool
	Fallible     string
	IntLiteral   string
	NonZero      bool
	NonNegative  bool
	MaxExclusive int
	Const        bool
	Void         bool
	XDPAction    bool
	TCAction     bool
	CgroupAction bool
	LSMAction    bool
}

func validateFuncBody(decl ast.FuncDecl, known map[string]bool, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl, userStructs map[string]ast.TypeDecl, consts map[string]ast.ConstDecl, sections []sectionSpec, funcs map[string]ast.FuncDecl) []diag.Diagnostic {
	locals := initialFuncLocals(decl, consts)
	checker := funcBodyChecker{
		maps:           maps,
		structs:        structs,
		known:          known,
		userStructs:    userStructs,
		funcs:          funcs,
		programSection: programSectionName(sections),
		returnType:     valueType{Name: decl.Return.Name, Ref: decl.Return, Ptr: decl.Return.Ptr},
	}
	checker.checkStatements(decl.Body, locals)
	if !blockAlwaysReturns(decl.Body) {
		checker.add(diag.Diagnostic{
			Code:     "HZN1445",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("function %q must return i32 on every path", decl.Name),
			Primary:  decl.Span,
			Suggest:  "end the program with an explicit return, or make both branches of the final if return",
		})
	}
	return checker.diags
}

type funcBodyChecker struct {
	maps           map[string]ast.MapDecl
	structs        map[string]ast.TypeDecl
	known          map[string]bool
	userStructs    map[string]ast.TypeDecl
	funcs          map[string]ast.FuncDecl
	programSection string
	returnType     valueType
	diags          []diag.Diagnostic
}

func initialFuncLocals(decl ast.FuncDecl, consts map[string]ast.ConstDecl) map[string]valueType {
	locals := map[string]valueType{}
	for name, constant := range consts {
		if typ, ok := constDeclType(constant); ok {
			typ.Const = true
			locals[name] = typ
		}
	}
	for _, param := range decl.Params {
		if param.Name == "" {
			continue
		}
		locals[param.Name] = valueType{Name: param.Type.Name, Ref: param.Type, Ptr: param.Type.Ptr}
	}
	return locals
}

func programSectionName(sections []sectionSpec) string {
	if len(sections) == 1 {
		return sections[0].Attr.Name
	}
	return ""
}

func (c *funcBodyChecker) add(diags ...diag.Diagnostic) {
	c.diags = append(c.diags, diags...)
}

func (c *funcBodyChecker) typeOf(expr ast.Expr, locals map[string]valueType) (valueType, []diag.Diagnostic) {
	return typeOfExpr(expr, locals, c.maps, c.structs, c.funcs)
}

func (c *funcBodyChecker) checkStatements(stmts []ast.Stmt, locals map[string]valueType) {
	for _, stmt := range stmts {
		c.checkStmt(stmt, locals)
	}
}

func (c *funcBodyChecker) checkStmt(stmt ast.Stmt, locals map[string]valueType) {
	switch s := stmt.(type) {
	case ast.ShortVarStmt:
		c.checkShortVar(s, locals)
	case ast.VarDeclStmt:
		c.checkVarDecl(s, locals)
	case ast.AssignStmt:
		c.checkAssign(s, locals)
	case ast.ExprStmt:
		c.checkExprStmt(s, locals)
	case ast.ReturnStmt:
		c.checkReturn(s, locals)
	case ast.IfStmt:
		c.checkIf(s, locals)
	case ast.ForStmt:
		c.checkFor(s, locals)
	case ast.SwitchStmt:
		c.checkSwitch(s, locals)
	case ast.IncStmt:
		c.checkInc(s, locals)
	case ast.RawStmt:
		c.add(diag.Diagnostic{
			Code:     "HZN1400",
			Severity: diag.SeverityError,
			Message:  "unsupported statement form",
			Primary:  s.Span,
			Suggest:  "use Horizon's Go-shaped statement subset instead of raw text",
		})
	}
}

func (c *funcBodyChecker) checkVarDecl(s ast.VarDeclStmt, locals map[string]valueType) {
	typeDiags := validateLocalVarType(s.Type, c.known, c.userStructs)
	c.add(typeDiags...)
	typ, exprDiags := c.typeOf(s.Value, locals)
	c.add(exprDiags...)
	target := valueType{Name: s.Type.Name, Ref: s.Type, Ptr: s.Type.Ptr}
	nameInvalid := false
	if d, ok := c.localNameDiagnostic(s.Name, s.Span, locals); ok {
		c.add(d)
		nameInvalid = true
	}
	switch {
	case typ.Fallible != "":
		c.add(fallibleResultDiagnostic(s.Span, typ.Fallible))
	case typ.Void:
		c.add(diag.Diagnostic{
			Code:     "HZN1409",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("cannot assign void expression to %q", s.Name),
			Primary:  s.Span,
		})
	case isFixedArray(typ):
		c.add(fixedArrayLocalDiagnostic(s.Span, s.Name, typ))
	case len(exprDiags) == 0 && isTrackedPointer(typ):
		c.add(trackedPointerAliasDiagnostic(s.Span, s.Name, typ))
	case len(typeDiags) > 0:
		return
	case !assignable(target, typ):
		if d, ok := assignabilityDiagnostic(
			"HZN1484",
			fmt.Sprintf("cannot initialize var %q of type %s with %s", s.Name, typeName(target), typeName(typ)),
			target,
			typ,
			s.Value.GetSpan(),
		); ok {
			c.add(d)
		}
	default:
		if s.Name != "" && !nameInvalid {
			locals[s.Name] = target
		}
	}
}

func validateLocalVarType(ref ast.TypeRef, known map[string]bool, userStructs map[string]ast.TypeDecl) []diag.Diagnostic {
	var diags []diag.Diagnostic
	diags = append(diags, validateTypeRef(ref, known)...)
	switch {
	case ref.IsZero():
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1483",
			Severity: diag.SeverityError,
			Message:  "var declarations require an explicit local type",
			Primary:  ref.Span,
		})
	case ref.Ptr || ref.Elem != nil || len(ref.Args) > 0:
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1483",
			Severity: diag.SeverityError,
			Message:  "var declarations must use a scalar, bool, or declared struct type",
			Primary:  ref.Span,
			Suggest:  "keep nullable resources in short declarations from map lookup, ringbuf reserve, or packet helpers",
		})
	case ref.Name != "" && !known[ref.Name]:
		return diags
	case isScalar(ref.Name):
		return diags
	default:
		if _, ok := userStructs[ref.Name]; ok {
			return diags
		}
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1483",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("var declarations cannot use compiler-owned type %s", ref.Name),
			Primary:  ref.Span,
			Suggest:  "use compiler-owned context and packet header types only through helper calls",
		})
	}
	return diags
}

func (c *funcBodyChecker) checkShortVar(s ast.ShortVarStmt, locals map[string]valueType) {
	typ, exprDiags := c.typeOf(s.Value, locals)
	c.add(exprDiags...)
	nameInvalid := false
	if d, ok := c.localNameDiagnostic(s.Name, s.Span, locals); ok {
		c.add(d)
		nameInvalid = true
	}
	switch {
	case typ.Fallible != "":
		c.add(fallibleResultDiagnostic(s.Span, typ.Fallible))
	case typ.Void:
		c.add(diag.Diagnostic{
			Code:     "HZN1409",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("cannot assign void expression to %q", s.Name),
			Primary:  s.Span,
		})
	case isFixedArray(typ):
		c.add(fixedArrayLocalDiagnostic(s.Span, s.Name, typ))
	case len(exprDiags) == 0 && isTrackedPointer(typ) && !directTrackedPointerSource(s.Value, c.maps):
		c.add(trackedPointerAliasDiagnostic(s.Span, s.Name, typ))
		if s.Name != "" && !nameInvalid {
			locals[s.Name] = typ
		}
	default:
		if s.Name != "" && !nameInvalid {
			locals[s.Name] = typ
		}
	}
}

func (c *funcBodyChecker) localNameDiagnostic(name string, primary span.Span, locals map[string]valueType) (diag.Diagnostic, bool) {
	if name == "" {
		return diag.Diagnostic{}, false
	}
	if _, ok := locals[name]; ok {
		return diag.Diagnostic{
			Code:     "HZN1477",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("local %q is already in scope", name),
			Primary:  primary,
			Suggest:  "use `=` to update an existing local, or choose a fresh name for a new value",
		}, true
	}
	if _, ok := c.maps[name]; ok {
		return diag.Diagnostic{
			Code:     "HZN1477",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("local %q conflicts with a map declaration", name),
			Primary:  primary,
			Suggest:  "choose a local name that does not hide a package-scoped map",
		}, true
	}
	if compilerNamespace(name) {
		return diag.Diagnostic{
			Code:     "HZN1477",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("local %q conflicts with a compiler namespace", name),
			Primary:  primary,
			Suggest:  "compiler namespaces such as bpf, xdp, tc, cgroup, lsm, kprobe, and tracepoint are reserved",
		}, true
	}
	return diag.Diagnostic{}, false
}

func compilerNamespace(name string) bool {
	switch name {
	case "bpf", "xdp", "tc", "cgroup", "lsm", "kprobe", "kretprobe", "tracepoint":
		return true
	default:
		return false
	}
}

func (c *funcBodyChecker) checkAssign(s ast.AssignStmt, locals map[string]valueType) {
	target, targetDiags := c.typeOf(s.Target, locals)
	value, valueDiags := c.typeOf(s.Value, locals)
	targetHadErrors := len(targetDiags) > 0
	c.add(targetDiags...)
	c.add(valueDiags...)
	if c.rejectConstAssignment(s, target) || c.rejectInvalidAssignedValue(s, value, valueDiags) || c.rejectActionAssignment(s, target, value) || targetHadErrors {
		return
	}
	if c.validateAssignableTarget(s, target, value) {
		c.updateAssignedLocal(s, target, value, locals)
	}
}

func (c *funcBodyChecker) rejectConstAssignment(s ast.AssignStmt, target valueType) bool {
	if !target.Const {
		return false
	}
	c.add(diag.Diagnostic{
		Code:     "HZN1481",
		Severity: diag.SeverityError,
		Message:  "constants cannot be assigned",
		Primary:  s.Target.GetSpan(),
		Suggest:  "use `:=` for a fresh local value instead of assigning to a package constant",
	})
	return true
}

func (c *funcBodyChecker) rejectInvalidAssignedValue(s ast.AssignStmt, value valueType, valueDiags []diag.Diagnostic) bool {
	if value.Fallible != "" {
		c.add(fallibleResultDiagnostic(s.Span, value.Fallible))
		return true
	}
	if len(valueDiags) == 0 && isTrackedPointer(value) {
		c.add(trackedPointerAliasDiagnostic(s.Span, "", value))
		return true
	}
	return false
}

func (c *funcBodyChecker) rejectActionAssignment(s ast.AssignStmt, target valueType, value valueType) bool {
	if d, ok := actionAssignmentDiagnostic(s.Span, target, value); ok {
		c.add(d)
		return true
	}
	return false
}

func actionAssignmentDiagnostic(primary span.Span, target valueType, value valueType) (diag.Diagnostic, bool) {
	switch {
	case target.XDPAction && !value.XDPAction:
		return diag.Diagnostic{Code: "HZN1448", Severity: diag.SeverityError, Message: "XDP action locals can only be assigned named xdp actions", Primary: primary, Suggest: "assign xdp.Pass, xdp.Drop, xdp.Aborted, xdp.Tx, or xdp.Redirect"}, true
	case target.TCAction && !value.TCAction:
		return diag.Diagnostic{Code: "HZN1450", Severity: diag.SeverityError, Message: "TC action locals can only be assigned named tc actions", Primary: primary, Suggest: "assign tc.OK, tc.Shot, tc.Reclassify, tc.Pipe, tc.Stolen, or tc.Redirect"}, true
	case target.CgroupAction && !value.CgroupAction:
		return diag.Diagnostic{Code: "HZN1454", Severity: diag.SeverityError, Message: "cgroup action locals can only be assigned named cgroup actions", Primary: primary, Suggest: "assign cgroup.Allow or cgroup.Deny"}, true
	case target.LSMAction && !value.LSMAction:
		return diag.Diagnostic{Code: "HZN1459", Severity: diag.SeverityError, Message: "LSM action locals can only be assigned named lsm actions", Primary: primary, Suggest: "assign lsm.Allow or lsm.Deny"}, true
	default:
		return diag.Diagnostic{}, false
	}
}

func (c *funcBodyChecker) validateAssignableTarget(s ast.AssignStmt, target valueType, value valueType) bool {
	switch {
	case target.Void:
		c.add(diag.Diagnostic{Code: "HZN1401", Severity: diag.SeverityError, Message: "assignment target is not addressable", Primary: s.Span})
		return false
	case isFixedArray(target):
		c.add(diag.Diagnostic{
			Code:     "HZN1431",
			Severity: diag.SeverityError,
			Message:  "fixed array fields cannot be assigned as values in Horizon v0",
			Primary:  s.Span,
			Suggest:  "write fixed array fields through compiler-known helpers such as bpf.current_comm(&event.comm)",
		})
		return false
	case isFixedArray(value):
		c.add(fixedArrayValueDiagnostic(s.Span))
		return false
	case !assignable(target, value):
		if d, ok := assignabilityDiagnostic(
			"HZN1402",
			fmt.Sprintf("cannot assign %s to %s", typeName(value), typeName(target)),
			target,
			value,
			s.Value.GetSpan(),
		); ok {
			c.add(d)
		}
		return false
	}
	return true
}

func (c *funcBodyChecker) updateAssignedLocal(s ast.AssignStmt, target valueType, value valueType, locals map[string]valueType) {
	ident, ok := s.Target.(ast.IdentExpr)
	if !ok || ident.Name == "" {
		return
	}
	if _, ok := locals[ident.Name]; !ok {
		return
	}
	updated := target
	updated.IntLiteral = ""
	updated.NonZero = false
	updated.NonNegative = false
	updated.MaxExclusive = 0
	if value.IntLiteral != "" {
		updated.IntLiteral = value.IntLiteral
	}
	if valueKnownNonZero(value) {
		updated.NonZero = true
	}
	if valueKnownNonNegative(value) {
		updated.NonNegative = true
	}
	updated.MaxExclusive = value.MaxExclusive
	locals[ident.Name] = updated
}

func (c *funcBodyChecker) checkExprStmt(s ast.ExprStmt, locals map[string]valueType) {
	typ, exprDiags := c.typeOf(s.Expr, locals)
	c.add(exprDiags...)
	if typ.Fallible != "" {
		c.add(fallibleResultDiagnostic(s.Span, typ.Fallible))
	}
}

func (c *funcBodyChecker) checkReturn(s ast.ReturnStmt, locals map[string]valueType) {
	value, exprDiags := c.typeOf(s.Value, locals)
	c.add(exprDiags...)
	primary := s.Span
	if s.Value != nil {
		primary = s.Value.GetSpan()
	}
	if c.programSection == "" {
		if d, ok := helperReturnDiagnostic(c.returnType, value, s.Value != nil, primary); ok {
			c.add(d)
		}
		return
	}
	if d, ok := returnDiagnostic(c.programSection, value, s.Value != nil, primary); ok {
		c.add(d)
	}
}

func (c *funcBodyChecker) checkSwitch(s ast.SwitchStmt, locals map[string]valueType) {
	value, valueDiags := c.typeOf(s.Value, locals)
	c.add(valueDiags...)
	valuePrimary := s.Span
	if s.Value != nil {
		valuePrimary = s.Value.GetSpan()
	}
	if value.Fallible != "" {
		c.add(fallibleResultDiagnostic(valuePrimary, value.Fallible))
	}
	if len(valueDiags) == 0 && !switchableValue(value) {
		c.add(diag.Diagnostic{
			Code:     "HZN1490",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("switch value must be a scalar or bool, got %s", typeName(value)),
			Primary:  valuePrimary,
			Suggest:  "switch over explicit scalar values, named action values, or bool; keep resources behind nil-checked if statements",
		})
	}
	defaults := 0
	for _, swcase := range s.Cases {
		if swcase.Default {
			defaults++
			if defaults > 1 {
				c.add(diag.Diagnostic{
					Code:     "HZN1491",
					Severity: diag.SeverityError,
					Message:  "switch has more than one default case",
					Primary:  swcase.Span,
				})
			}
		} else if len(swcase.Values) == 0 {
			c.add(diag.Diagnostic{
				Code:     "HZN1491",
				Severity: diag.SeverityError,
				Message:  "case requires at least one value",
				Primary:  swcase.Span,
			})
		}
		for _, caseExpr := range swcase.Values {
			caseType, caseDiags := c.typeOf(caseExpr, locals)
			c.add(caseDiags...)
			casePrimary := swcase.Span
			if caseExpr != nil {
				casePrimary = caseExpr.GetSpan()
			}
			if caseType.Fallible != "" {
				c.add(fallibleResultDiagnostic(casePrimary, caseType.Fallible))
				continue
			}
			if !switchCaseConstant(caseExpr, locals) {
				c.add(diag.Diagnostic{
					Code:     "HZN1493",
					Severity: diag.SeverityError,
					Message:  "case values must be compile-time constants",
					Primary:  casePrimary,
					Suggest:  "use integer or bool literals, package constants, enum values, or compiler-known action/protocol constants",
				})
			}
			if len(valueDiags) == 0 && len(caseDiags) == 0 && !switchCaseCompatible(value, caseType) {
				c.add(diag.Diagnostic{
					Code:     "HZN1492",
					Severity: diag.SeverityError,
					Message:  fmt.Sprintf("case value %s is not compatible with switch value %s", typeName(caseType), typeName(value)),
					Primary:  casePrimary,
					Suggest:  "case values must have the same scalar width, a fitting integer literal, or the same named action family",
				})
			}
		}
		c.checkStatements(swcase.Body, cloneValueTypes(locals))
	}
}

func switchCaseConstant(expr ast.Expr, locals map[string]valueType) bool {
	switch e := expr.(type) {
	case ast.IntExpr, ast.BoolExpr:
		return true
	case ast.IdentExpr:
		local, ok := locals[e.Name]
		return ok && local.Const
	case ast.SelectorExpr:
		root, _, ok := selectorParts(e)
		return ok && compilerNamespace(root)
	case ast.UnaryExpr:
		return e.Op == "-" && switchCaseConstant(e.Expr, locals)
	case ast.BinaryExpr:
		return switchCaseConstant(e.Left, locals) && switchCaseConstant(e.Right, locals)
	default:
		return false
	}
}

func switchableValue(typ valueType) bool {
	if typ.Ptr || typ.MaybeNil || typ.Resource || typ.Void || isFixedArray(typ) {
		return false
	}
	return typ.Name == "bool" || integerOperand(typ)
}

func switchCaseCompatible(value valueType, caseType valueType) bool {
	if actionFamily(value) != "" || actionFamily(caseType) != "" {
		return actionFamily(value) != "" && actionFamily(value) == actionFamily(caseType)
	}
	if value.Name == "bool" || caseType.Name == "bool" {
		return value.Name == "bool" && caseType.Name == "bool" && !value.Ptr && !caseType.Ptr
	}
	if !integerOperand(value) || !integerOperand(caseType) {
		return false
	}
	if caseType.Name == "untyped_int" {
		return assignable(value, caseType)
	}
	if value.Name == "untyped_int" {
		return true
	}
	return value.Name == caseType.Name
}

func actionFamily(typ valueType) string {
	switch {
	case typ.XDPAction:
		return "xdp"
	case typ.TCAction:
		return "tc"
	case typ.CgroupAction:
		return "cgroup"
	case typ.LSMAction:
		return "lsm"
	default:
		return ""
	}
}

func helperReturnDiagnostic(target valueType, value valueType, hasValue bool, primary span.Span) (diag.Diagnostic, bool) {
	if !hasValue {
		return diag.Diagnostic{
			Code:     "HZN1504",
			Severity: diag.SeverityError,
			Message:  "helper functions must return an explicit scalar or bool value",
			Primary:  primary,
			Suggest:  "return a value matching the helper signature",
		}, true
	}
	if isFixedArray(value) {
		return diag.Diagnostic{
			Code:     "HZN1432",
			Severity: diag.SeverityError,
			Message:  "fixed array values cannot be returned in Horizon v0",
			Primary:  primary,
			Suggest:  "keep fixed arrays inside typed records and pass field addresses to compiler-known helpers",
		}, true
	}
	if !assignable(target, value) {
		if d, ok := assignabilityDiagnostic(
			"HZN1505",
			fmt.Sprintf("cannot return %s from helper returning %s", typeName(value), typeName(target)),
			target,
			value,
			primary,
		); ok {
			return d, true
		}
		return diag.Diagnostic{Code: "HZN1505", Severity: diag.SeverityError, Message: fmt.Sprintf("cannot return %s from helper returning %s", typeName(value), typeName(target)), Primary: primary}, true
	}
	return diag.Diagnostic{}, false
}

func returnDiagnostic(programSection string, value valueType, hasValue bool, primary span.Span) (diag.Diagnostic, bool) {
	if !hasValue {
		return diag.Diagnostic{
			Code:     "HZN1476",
			Severity: diag.SeverityError,
			Message:  "return statements in Horizon eBPF programs must include an explicit i32 value",
			Primary:  primary,
			Suggest:  "write `return 0` for successful tracing programs or return a named action for packet and policy programs",
		}, true
	}
	if hasValue && isFixedArray(value) {
		return diag.Diagnostic{
			Code:     "HZN1432",
			Severity: diag.SeverityError,
			Message:  "fixed array values cannot be returned in Horizon v0",
			Primary:  primary,
			Suggest:  "keep fixed arrays inside typed records and pass field addresses to compiler-known helpers",
		}, true
	}
	if d, ok := requiredActionReturnDiagnostic(programSection, value, primary); ok {
		return d, true
	}
	if d, ok := foreignActionReturnDiagnostic(programSection, value, primary); ok {
		return d, true
	}
	if hasValue && !assignable(valueType{Name: "i32"}, value) {
		if d, ok := integerLiteralRangeDiagnostic(valueType{Name: "i32"}, value, primary); ok {
			return d, true
		}
		return diag.Diagnostic{Code: "HZN1403", Severity: diag.SeverityError, Message: fmt.Sprintf("cannot return %s from i32 program", typeName(value)), Primary: primary}, true
	}
	return diag.Diagnostic{}, false
}

func requiredActionReturnDiagnostic(programSection string, value valueType, primary span.Span) (diag.Diagnostic, bool) {
	switch {
	case programSection == "xdp" && !value.XDPAction:
		return diag.Diagnostic{Code: "HZN1448", Severity: diag.SeverityError, Message: "XDP programs must return a named xdp action", Primary: primary, Suggest: "return xdp.Pass, xdp.Drop, xdp.Aborted, xdp.Tx, or xdp.Redirect"}, true
	case programSection == "tc" && !value.TCAction:
		return diag.Diagnostic{Code: "HZN1450", Severity: diag.SeverityError, Message: "TC programs must return a named tc action", Primary: primary, Suggest: "return tc.OK, tc.Shot, tc.Reclassify, tc.Pipe, tc.Stolen, or tc.Redirect"}, true
	case programSection == "cgroup" && !value.CgroupAction:
		return diag.Diagnostic{Code: "HZN1454", Severity: diag.SeverityError, Message: "cgroup programs must return a named cgroup action", Primary: primary, Suggest: "return cgroup.Allow or cgroup.Deny"}, true
	case programSection == "lsm" && !value.LSMAction:
		return diag.Diagnostic{Code: "HZN1459", Severity: diag.SeverityError, Message: "LSM programs must return a named lsm action", Primary: primary, Suggest: "return lsm.Allow or lsm.Deny"}, true
	default:
		return diag.Diagnostic{}, false
	}
}

func foreignActionReturnDiagnostic(programSection string, value valueType, primary span.Span) (diag.Diagnostic, bool) {
	switch {
	case programSection != "" && programSection != "xdp" && value.XDPAction:
		return diag.Diagnostic{Code: "HZN1449", Severity: diag.SeverityError, Message: fmt.Sprintf("@%s programs cannot return XDP actions", programSection), Primary: primary, Suggest: "return 0 from tracing programs; XDP actions are only valid in @xdp programs"}, true
	case programSection != "" && programSection != "tc" && value.TCAction:
		return diag.Diagnostic{Code: "HZN1451", Severity: diag.SeverityError, Message: fmt.Sprintf("@%s programs cannot return TC actions", programSection), Primary: primary, Suggest: `return 0 from tracing programs; TC actions are only valid in @tc programs`}, true
	case programSection != "" && programSection != "cgroup" && value.CgroupAction:
		return diag.Diagnostic{Code: "HZN1455", Severity: diag.SeverityError, Message: fmt.Sprintf("@%s programs cannot return cgroup actions", programSection), Primary: primary, Suggest: `return 0 from tracing programs; cgroup actions are only valid in @cgroup programs`}, true
	case programSection != "" && programSection != "lsm" && value.LSMAction:
		return diag.Diagnostic{Code: "HZN1460", Severity: diag.SeverityError, Message: fmt.Sprintf("@%s programs cannot return LSM actions", programSection), Primary: primary, Suggest: `return 0 from tracing programs; LSM actions are only valid in @lsm programs`}, true
	default:
		return diag.Diagnostic{}, false
	}
}

func (c *funcBodyChecker) checkIf(s ast.IfStmt, locals map[string]valueType) {
	ifLocals := cloneValueTypes(locals)
	if s.Init != nil {
		c.checkStmt(s.Init, ifLocals)
	}
	cond, exprDiags := c.typeOf(s.Cond, ifLocals)
	c.add(exprDiags...)
	c.add(validateCondition(cond, s.Cond.GetSpan())...)
	thenLocals := cloneValueTypes(ifLocals)
	elseLocals := cloneValueTypes(ifLocals)
	thenFacts, elseFacts := conditionFacts(s.Cond, ifLocals)
	applyFacts(thenLocals, thenFacts)
	applyFacts(elseLocals, elseFacts)
	c.checkStatements(s.Then, thenLocals)
	c.checkStatements(s.Else, elseLocals)
	if blockAlwaysReturns(s.Then) {
		applyFacts(locals, elseFacts)
	}
	if blockAlwaysReturns(s.Else) {
		applyFacts(locals, thenFacts)
	}
}

type valueFacts struct {
	NonZero      map[string]bool
	NonNegative  map[string]bool
	MaxExclusive map[string]int
}

func conditionFacts(cond ast.Expr, locals map[string]valueType) (valueFacts, valueFacts) {
	binary, ok := cond.(ast.BinaryExpr)
	if !ok {
		return valueFacts{}, valueFacts{}
	}
	if binary.Op == "&&" {
		leftThen, _ := conditionFacts(binary.Left, locals)
		rightThen, _ := conditionFacts(binary.Right, locals)
		return mergeFacts(leftThen, rightThen), valueFacts{}
	}
	thenFacts, elseFacts := nonZeroFacts(binary, locals)
	addRangeFacts(binary, locals, &thenFacts, &elseFacts)
	return thenFacts, elseFacts
}

func mergeFacts(left valueFacts, right valueFacts) valueFacts {
	out := valueFacts{}
	mergeBoolFacts(&out.NonZero, left.NonZero)
	mergeBoolFacts(&out.NonZero, right.NonZero)
	mergeBoolFacts(&out.NonNegative, left.NonNegative)
	mergeBoolFacts(&out.NonNegative, right.NonNegative)
	mergeMaxFacts(&out.MaxExclusive, left.MaxExclusive)
	mergeMaxFacts(&out.MaxExclusive, right.MaxExclusive)
	return out
}

func mergeBoolFacts(dst *map[string]bool, src map[string]bool) {
	for name := range src {
		if *dst == nil {
			*dst = map[string]bool{}
		}
		(*dst)[name] = true
	}
}

func mergeMaxFacts(dst *map[string]int, src map[string]int) {
	for name, value := range src {
		addMaxExclusiveFact(dst, name, value)
	}
}

func nonZeroFacts(binary ast.BinaryExpr, locals map[string]valueType) (valueFacts, valueFacts) {
	leftName, leftIdent := identName(binary.Left)
	rightName, rightIdent := identName(binary.Right)
	leftZero := integerZeroExpr(binary.Left, locals)
	rightZero := integerZeroExpr(binary.Right, locals)
	switch binary.Op {
	case "!=":
		if leftIdent && rightZero {
			return valueFacts{NonZero: map[string]bool{leftName: true}}, valueFacts{}
		}
		if rightIdent && leftZero {
			return valueFacts{NonZero: map[string]bool{rightName: true}}, valueFacts{}
		}
	case "==":
		if leftIdent && rightZero {
			return valueFacts{}, valueFacts{NonZero: map[string]bool{leftName: true}}
		}
		if rightIdent && leftZero {
			return valueFacts{}, valueFacts{NonZero: map[string]bool{rightName: true}}
		}
	case ">", "<":
		if leftIdent && rightZero {
			return valueFacts{NonZero: map[string]bool{leftName: true}}, valueFacts{}
		}
		if rightIdent && leftZero {
			return valueFacts{NonZero: map[string]bool{rightName: true}}, valueFacts{}
		}
	}
	return valueFacts{}, valueFacts{}
}

func addRangeFacts(binary ast.BinaryExpr, locals map[string]valueType, thenFacts *valueFacts, elseFacts *valueFacts) {
	leftName, leftIdent := identName(binary.Left)
	rightName, rightIdent := identName(binary.Right)
	leftValue, leftValueOK := integerExprValue(binary.Left, locals)
	rightValue, rightValueOK := integerExprValue(binary.Right, locals)
	switch binary.Op {
	case "<":
		if leftIdent && rightValueOK {
			addMaxExclusiveFact(&thenFacts.MaxExclusive, leftName, rightValue)
			addMinInclusiveFact(&elseFacts.NonNegative, leftName, rightValue)
		}
		if rightIdent && leftValueOK {
			addMinInclusiveFact(&thenFacts.NonNegative, rightName, leftValue+1)
			addMaxExclusiveFact(&elseFacts.MaxExclusive, rightName, leftValue+1)
		}
	case "<=":
		if leftIdent && rightValueOK {
			addMaxExclusiveFact(&thenFacts.MaxExclusive, leftName, rightValue+1)
			addMinInclusiveFact(&elseFacts.NonNegative, leftName, rightValue+1)
		}
		if rightIdent && leftValueOK {
			addMinInclusiveFact(&thenFacts.NonNegative, rightName, leftValue)
			addMaxExclusiveFact(&elseFacts.MaxExclusive, rightName, leftValue)
		}
	case ">":
		if leftIdent && rightValueOK {
			addMinInclusiveFact(&thenFacts.NonNegative, leftName, rightValue+1)
			addMaxExclusiveFact(&elseFacts.MaxExclusive, leftName, rightValue+1)
		}
		if rightIdent && leftValueOK {
			addMaxExclusiveFact(&thenFacts.MaxExclusive, rightName, leftValue)
			addMinInclusiveFact(&elseFacts.NonNegative, rightName, leftValue)
		}
	case ">=":
		if leftIdent && rightValueOK {
			addMinInclusiveFact(&thenFacts.NonNegative, leftName, rightValue)
			addMaxExclusiveFact(&elseFacts.MaxExclusive, leftName, rightValue)
		}
		if rightIdent && leftValueOK {
			addMaxExclusiveFact(&thenFacts.MaxExclusive, rightName, leftValue+1)
			addMinInclusiveFact(&elseFacts.NonNegative, rightName, leftValue+1)
		}
	}
}

func addMaxExclusiveFact(facts *map[string]int, name string, value int) {
	if value <= 0 {
		return
	}
	if *facts == nil {
		*facts = map[string]int{}
	}
	if current, ok := (*facts)[name]; !ok || value < current {
		(*facts)[name] = value
	}
}

func addMinInclusiveFact(facts *map[string]bool, name string, value int) {
	if value > 0 {
		return
	}
	if *facts == nil {
		*facts = map[string]bool{}
	}
	(*facts)[name] = true
}

func identName(expr ast.Expr) (string, bool) {
	ident, ok := expr.(ast.IdentExpr)
	return ident.Name, ok && ident.Name != ""
}

func integerZeroExpr(expr ast.Expr, locals map[string]valueType) bool {
	value, ok := integerExprValue(expr, locals)
	return ok && value == 0
}

func integerExprValue(expr ast.Expr, locals map[string]valueType) (int, bool) {
	switch e := expr.(type) {
	case ast.IntExpr:
		return literalInt(e.Value)
	case ast.UnaryExpr:
		if e.Op != "-" {
			return 0, false
		}
		if lit, ok := e.Expr.(ast.IntExpr); ok {
			return literalInt(negateIntegerLiteral(lit.Value))
		}
	case ast.IdentExpr:
		local, ok := locals[e.Name]
		if ok && local.IntLiteral != "" {
			return literalInt(local.IntLiteral)
		}
	}
	return 0, false
}

func applyFacts(locals map[string]valueType, facts valueFacts) {
	for name := range facts.NonZero {
		typ, ok := locals[name]
		if !ok || !integerOperand(typ) {
			continue
		}
		typ.NonZero = true
		locals[name] = typ
	}
	for name := range facts.NonNegative {
		typ, ok := locals[name]
		if !ok || !integerOperand(typ) {
			continue
		}
		typ.NonNegative = true
		locals[name] = typ
	}
	for name, max := range facts.MaxExclusive {
		typ, ok := locals[name]
		if !ok || !integerOperand(typ) {
			continue
		}
		if typ.MaxExclusive == 0 || max < typ.MaxExclusive {
			typ.MaxExclusive = max
		}
		locals[name] = typ
	}
}

func (c *funcBodyChecker) checkFor(s ast.ForStmt, locals map[string]valueType) {
	loopLocals := cloneValueTypes(locals)
	if s.Init != nil {
		c.checkStmt(s.Init, loopLocals)
	}
	if s.Cond != nil {
		cond, exprDiags := c.typeOf(s.Cond, loopLocals)
		c.add(exprDiags...)
		c.add(validateCondition(cond, s.Cond.GetSpan())...)
	}
	if s.Post != nil {
		c.checkStmt(s.Post, loopLocals)
	}
	c.checkStatements(s.Body, cloneValueTypes(loopLocals))
}

func (c *funcBodyChecker) checkInc(s ast.IncStmt, locals map[string]valueType) {
	local, ok := locals[s.Name]
	if !ok {
		c.add(diag.Diagnostic{Code: "HZN1404", Severity: diag.SeverityError, Message: fmt.Sprintf("unknown identifier %q", s.Name), Primary: s.Span})
		return
	}
	if local.Const {
		c.add(diag.Diagnostic{
			Code:     "HZN1481",
			Severity: diag.SeverityError,
			Message:  "constants cannot be incremented",
			Primary:  s.Span,
			Suggest:  "use `:=` for a fresh local counter instead of incrementing a package constant",
		})
		return
	}
	if !isIntegerScalar(local.Name) && local.Name != "untyped_int" {
		c.add(diag.Diagnostic{Code: "HZN1408", Severity: diag.SeverityError, Message: fmt.Sprintf("%s requires an integer variable, got %s", s.Op, typeName(local)), Primary: s.Span})
	}
}

func blockAlwaysReturns(stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		if stmtAlwaysReturns(stmt) {
			return true
		}
	}
	return false
}

func stmtAlwaysReturns(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case ast.ReturnStmt:
		return true
	case ast.IfStmt:
		return blockAlwaysReturns(s.Then) && blockAlwaysReturns(s.Else)
	case ast.SwitchStmt:
		hasDefault := false
		for _, c := range s.Cases {
			if c.Default {
				hasDefault = true
			}
			if !blockAlwaysReturns(c.Body) {
				return false
			}
		}
		return hasDefault && len(s.Cases) > 0
	default:
		return false
	}
}

func cloneValueTypes(in map[string]valueType) map[string]valueType {
	out := make(map[string]valueType, len(in))
	for name, typ := range in {
		out[name] = typ
	}
	return out
}

func typeOfExpr(expr ast.Expr, locals map[string]valueType, maps map[string]ast.MapDecl, structs map[string]ast.TypeDecl, funcs map[string]ast.FuncDecl) (valueType, []diag.Diagnostic) {
	return exprTyper{
		locals:  locals,
		maps:    maps,
		structs: structs,
		funcs:   funcs,
	}.typeOf(expr)
}

type exprTyper struct {
	locals  map[string]valueType
	maps    map[string]ast.MapDecl
	structs map[string]ast.TypeDecl
	funcs   map[string]ast.FuncDecl
}

func (t exprTyper) typeOf(expr ast.Expr) (valueType, []diag.Diagnostic) {
	switch e := expr.(type) {
	case nil:
		return valueType{Void: true}, nil
	case ast.IdentExpr:
		return t.ident(e)
	case ast.IntExpr:
		return valueType{Name: "untyped_int", IntLiteral: e.Value, NonZero: literalNonZero(e.Value), NonNegative: literalNonNegative(e.Value)}, nil
	case ast.BoolExpr:
		return valueType{Name: "bool"}, nil
	case ast.NilExpr:
		return valueType{Name: "nil"}, nil
	case ast.SelectorExpr:
		return t.selector(e)
	case ast.UnaryExpr:
		return t.unary(e)
	case ast.BinaryExpr:
		return t.binary(e)
	case ast.StructLiteralExpr:
		return t.structLiteral(e)
	case ast.CallExpr:
		return t.call(e)
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

func (t exprTyper) ident(e ast.IdentExpr) (valueType, []diag.Diagnostic) {
	if local, ok := t.locals[e.Name]; ok {
		return local, nil
	}
	if m, ok := t.maps[e.Name]; ok {
		return valueType{Name: string(m.Kind), Ref: m.Val}, nil
	}
	return valueType{}, []diag.Diagnostic{{
		Code:     "HZN1404",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("unknown identifier %q", e.Name),
		Primary:  e.Span,
	}}
}

func (t exprTyper) selector(e ast.SelectorExpr) (valueType, []diag.Diagnostic) {
	if typ, diags, ok := t.compilerSelector(e); ok {
		return typ, diags
	}
	return t.fieldSelector(e)
}

func (t exprTyper) compilerSelector(e ast.SelectorExpr) (valueType, []diag.Diagnostic, bool) {
	root, field, ok := selectorParts(e)
	if !ok {
		return valueType{}, nil, false
	}
	switch root {
	case "bpf":
		return valueType{Name: "helper:" + field}, nil, true
	case "xdp":
		if typ, ok := xdpSelectorType(field); ok {
			return typ, nil, true
		}
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1434",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown XDP symbol xdp.%s", field),
			Primary:  e.Span,
			Suggest:  "use XDP actions such as xdp.Pass or packet constants such as xdp.IPProtoTCP",
		}}, true
	case "tc":
		if typ, ok := tcSelectorType(field); ok {
			return typ, nil, true
		}
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1452",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown TC symbol tc.%s", field),
			Primary:  e.Span,
			Suggest:  "use TC actions such as tc.OK or tc.Shot",
		}}, true
	case "cgroup":
		if typ, ok := cgroupSelectorType(field); ok {
			return typ, nil, true
		}
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1456",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown cgroup symbol cgroup.%s", field),
			Primary:  e.Span,
			Suggest:  "use cgroup actions, named protocol constants, or helpers such as cgroup.dst_port(ctx)",
		}}, true
	case "lsm":
		if typ, ok := lsmSelectorType(field); ok {
			return typ, nil, true
		}
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1461",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown LSM symbol lsm.%s", field),
			Primary:  e.Span,
			Suggest:  "use LSM actions such as lsm.Allow or lsm.Deny",
		}}, true
	default:
		return valueType{}, nil, false
	}
}

func (t exprTyper) fieldSelector(e ast.SelectorExpr) (valueType, []diag.Diagnostic) {
	operand, diags := t.typeOf(e.Operand)
	if operand.Ptr {
		operand.Ptr = false
	}
	structDecl, ok := t.structs[operand.Name]
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
}

func (t exprTyper) unary(e ast.UnaryExpr) (valueType, []diag.Diagnostic) {
	operand, diags := t.typeOf(e.Expr)
	switch e.Op {
	case "&":
		operand.Ptr = true
		if len(diags) == 0 && !isFixedArray(operand) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1472",
				Severity: diag.SeverityError,
				Message:  "operator & is only supported for fixed array fields passed directly to compiler-known helpers",
				Primary:  e.Span,
				Suggest:  "avoid raw pointer authoring; use map lookup, ringbuf reserve, packet helpers, or pass &event.comm directly to bpf.current_comm",
			})
		}
		return operand, diags
	case "*":
		if len(diags) == 0 {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1473",
				Severity: diag.SeverityError,
				Message:  "explicit pointer dereference is not supported in Horizon v0",
				Primary:  e.Span,
				Suggest:  "read and write fields through nil-checked map, ringbuf, or packet helper locals instead of using *ptr",
			})
		}
		if operand.Ptr {
			operand.Ptr = false
			operand.MaybeNil = false
			operand.Resource = false
		}
		return operand, diags
	case "-":
		if operand.Void || operand.Name == "" {
			return valueType{Void: true}, diags
		}
		if operand.Name == "untyped_int" && !operand.Ptr && unaryIntegerLiteralOperand(e.Expr) {
			operand.IntLiteral = negateIntegerLiteral(operand.IntLiteral)
			operand.NonZero = literalNonZero(operand.IntLiteral)
			operand.NonNegative = literalNonNegative(operand.IntLiteral)
			return operand, diags
		}
		if isSignedIntegerScalar(operand.Name) && !operand.Ptr {
			return operand, diags
		}
		return valueType{Name: operand.Name}, append(diags, diag.Diagnostic{
			Code:     "HZN1471",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator - expects a signed integer operand, got %s", typeName(operand)),
			Primary:  e.Span,
			Suggest:  "write a negative integer literal directly or convert to a signed scalar such as i64 before negating",
		})
	case "!":
		if operand.Void || operand.Name == "" {
			return valueType{Void: true}, diags
		}
		if operand.Name == "bool" && !operand.Ptr {
			return valueType{Name: "bool"}, diags
		}
		return valueType{Name: "bool"}, append(diags, diag.Diagnostic{
			Code:     "HZN1442",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator ! expects bool operand, got %s", typeName(operand)),
			Primary:  e.Span,
		})
	default:
		return operand, diags
	}
}

func unaryIntegerLiteralOperand(expr ast.Expr) bool {
	switch e := expr.(type) {
	case ast.IntExpr:
		return e.Value != ""
	case ast.UnaryExpr:
		return e.Op == "-" && unaryIntegerLiteralOperand(e.Expr)
	default:
		return false
	}
}

func (t exprTyper) binary(e ast.BinaryExpr) (valueType, []diag.Diagnostic) {
	left, leftDiags := t.typeOf(e.Left)
	right, rightDiags := t.typeOf(e.Right)
	typ, opDiags := typeOfBinaryExpr(e, left, right)
	diags := append(leftDiags, rightDiags...)
	diags = append(diags, opDiags...)
	return typ, diags
}

func validateCondition(cond valueType, primary span.Span) []diag.Diagnostic {
	if cond.Void || cond.Name == "" {
		return nil
	}
	if cond.Name == "bool" && !cond.Ptr {
		return nil
	}
	return []diag.Diagnostic{{
		Code:     "HZN1443",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("condition must be bool, got %s", typeName(cond)),
		Primary:  primary,
		Suggest:  "compare explicitly, for example `value != 0` or `ptr != nil`",
	}}
}

func typeOfBinaryExpr(expr ast.BinaryExpr, left valueType, right valueType) (valueType, []diag.Diagnostic) {
	if left.Void || right.Void {
		return valueType{Void: true}, nil
	}
	if left.Fallible != "" || right.Fallible != "" {
		if fallibleResultIsChecked(expr.Op, left, right) {
			return valueType{Name: "bool"}, nil
		}
		operation := left.Fallible
		if operation == "" {
			operation = right.Fallible
		}
		return valueType{Void: true}, []diag.Diagnostic{fallibleResultDiagnostic(expr.Span, operation)}
	}
	switch {
	case isLogicalOp(expr.Op):
		if left.Name == "bool" && right.Name == "bool" && !left.Ptr && !right.Ptr {
			return valueType{Name: "bool"}, nil
		}
		return valueType{Name: "bool"}, []diag.Diagnostic{{
			Code:     "HZN1442",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator %s expects bool operands, got %s and %s", expr.Op, typeName(left), typeName(right)),
			Primary:  expr.Span,
		}}
	case isEqualityOp(expr.Op):
		if comparable(left, right) {
			if d, ok := integerOperandRangeDiagnostic(expr, left, right); ok {
				return valueType{Name: "bool"}, []diag.Diagnostic{d}
			}
			return valueType{Name: "bool"}, nil
		}
		return valueType{Name: "bool"}, []diag.Diagnostic{{
			Code:     "HZN1440",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator %s cannot compare %s and %s", expr.Op, typeName(left), typeName(right)),
			Primary:  expr.Span,
		}}
	case isComparisonOp(expr.Op):
		if integerOperand(left) && integerOperand(right) && compatibleIntegerOperands(left, right) {
			if d, ok := integerOperandRangeDiagnostic(expr, left, right); ok {
				return valueType{Name: "bool"}, []diag.Diagnostic{d}
			}
			return valueType{Name: "bool"}, nil
		}
		return valueType{Name: "bool"}, []diag.Diagnostic{{
			Code:     "HZN1440",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator %s expects compatible integer operands, got %s and %s", expr.Op, typeName(left), typeName(right)),
			Primary:  expr.Span,
		}}
	case isShiftOp(expr.Op):
		if integerOperand(left) && integerOperand(right) {
			if d, ok := shiftCountDiagnostic(expr, left, right); ok {
				return integerResult(left, right), []diag.Diagnostic{d}
			}
			return integerResult(left, right), nil
		}
	case isIntegerBinaryOp(expr.Op):
		if integerOperand(left) && integerOperand(right) && compatibleIntegerOperands(left, right) {
			if d, ok := integerOperandRangeDiagnostic(expr, left, right); ok {
				return integerResult(left, right), []diag.Diagnostic{d}
			}
			if d, ok := zeroDivisorDiagnostic(expr, right); ok {
				return integerResult(left, right), []diag.Diagnostic{d}
			}
			return integerResult(left, right), nil
		}
	}
	if isShiftOp(expr.Op) || isIntegerBinaryOp(expr.Op) {
		return valueType{Name: "untyped_int"}, []diag.Diagnostic{{
			Code:     "HZN1441",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator %s expects compatible integer operands, got %s and %s", expr.Op, typeName(left), typeName(right)),
			Primary:  expr.Span,
		}}
	}
	return valueType{Void: true}, []diag.Diagnostic{{
		Code:     "HZN1444",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("unsupported binary operator %q", expr.Op),
		Primary:  expr.Span,
	}}
}

func comparable(left valueType, right valueType) bool {
	if left.Name == "nil" {
		return right.Ptr || right.MaybeNil
	}
	if right.Name == "nil" {
		return left.Ptr || left.MaybeNil
	}
	if left.Ptr || right.Ptr {
		return left.Ptr == right.Ptr && left.Name == right.Name
	}
	if left.Name == "bool" || right.Name == "bool" {
		return left.Name == right.Name
	}
	return integerOperand(left) && integerOperand(right) && compatibleIntegerOperands(left, right)
}

func integerResult(left valueType, right valueType) valueType {
	if left.Name != "untyped_int" {
		left.IntLiteral = ""
		left.NonZero = false
		left.NonNegative = false
		left.MaxExclusive = 0
		return left
	}
	right.IntLiteral = ""
	right.NonZero = false
	right.NonNegative = false
	right.MaxExclusive = 0
	return right
}

func integerOperand(t valueType) bool {
	return t.Name == "untyped_int" || isIntegerScalar(t.Name)
}

func compatibleIntegerOperands(left valueType, right valueType) bool {
	return left.Name == "untyped_int" || right.Name == "untyped_int" || left.Name == right.Name
}

func isLogicalOp(op string) bool {
	return op == "&&" || op == "||"
}

func isEqualityOp(op string) bool {
	return op == "==" || op == "!="
}

func isComparisonOp(op string) bool {
	switch op {
	case "<", "<=", ">", ">=":
		return true
	default:
		return false
	}
}

func fallibleResultIsChecked(op string, left valueType, right valueType) bool {
	if !isEqualityOp(op) && !isComparisonOp(op) {
		return false
	}
	if left.Fallible != "" && right.Fallible != "" {
		return false
	}
	if left.Fallible != "" {
		return integerOperand(left) && integerOperand(right) && compatibleIntegerOperands(left, right)
	}
	if right.Fallible != "" {
		return integerOperand(left) && integerOperand(right) && compatibleIntegerOperands(left, right)
	}
	return false
}

func isShiftOp(op string) bool {
	return op == "<<" || op == ">>"
}

func isIntegerBinaryOp(op string) bool {
	switch op {
	case "+", "-", "*", "/", "%", "&", "|", "^":
		return true
	default:
		return false
	}
}

func zeroDivisorDiagnostic(expr ast.BinaryExpr, divisor valueType) (diag.Diagnostic, bool) {
	if expr.Op != "/" && expr.Op != "%" {
		return diag.Diagnostic{}, false
	}
	value, ok := integerLiteralBig(divisor)
	if ok && value.Sign() == 0 {
		return diag.Diagnostic{
			Code:     "HZN1478",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("operator %s divisor cannot be literal zero", expr.Op),
			Primary:  expr.Right.GetSpan(),
			Suggest:  "use a non-zero constant or branch around dynamic divisors before dividing",
		}, true
	}
	if valueKnownNonZero(divisor) {
		return diag.Diagnostic{}, false
	}
	return diag.Diagnostic{
		Code:     "HZN1480",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("operator %s divisor must be proven non-zero", expr.Op),
		Primary:  expr.Right.GetSpan(),
		Suggest:  "guard the divisor with `if value == 0 { return 0 }` or use a non-zero constant before dividing",
	}, true
}

func shiftCountDiagnostic(expr ast.BinaryExpr, value valueType, count valueType) (diag.Diagnostic, bool) {
	width := integerBitWidth(value.Name)
	if width == 0 {
		return diag.Diagnostic{}, false
	}
	lit, ok := integerLiteralBig(count)
	if ok {
		if lit.Sign() < 0 {
			return diag.Diagnostic{
				Code:     "HZN1479",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("operator %s shift count cannot be negative", expr.Op),
				Primary:  expr.Right.GetSpan(),
				Suggest:  "use a shift count from 0 up to one less than the left operand width",
			}, true
		}
		if lit.Cmp(big.NewInt(int64(width))) >= 0 {
			return diag.Diagnostic{
				Code:     "HZN1479",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("operator %s shift count %s is outside the %s width", expr.Op, lit.String(), typeName(value)),
				Primary:  expr.Right.GetSpan(),
				Suggest:  fmt.Sprintf("use a shift count from 0 to %d for %s values", width-1, typeName(value)),
			}, true
		}
		return diag.Diagnostic{}, false
	}
	if !valueKnownNonNegative(count) {
		return dynamicShiftCountDiagnostic(expr, value), true
	}
	if count.MaxExclusive == 0 || count.MaxExclusive > width {
		return dynamicShiftCountDiagnostic(expr, value), true
	}
	return diag.Diagnostic{}, false
}

func dynamicShiftCountDiagnostic(expr ast.BinaryExpr, value valueType) diag.Diagnostic {
	width := integerBitWidth(value.Name)
	return diag.Diagnostic{
		Code:     "HZN1482",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("operator %s shift count must be proven in range for %s", expr.Op, typeName(value)),
		Primary:  expr.Right.GetSpan(),
		Suggest:  fmt.Sprintf("guard the count with `if count >= %d { return 0 }` before shifting", width),
	}
}

func (t exprTyper) structLiteral(lit ast.StructLiteralExpr) (valueType, []diag.Diagnostic) {
	structDecl, ok := t.structs[lit.Type.Name]
	if !ok {
		return valueType{Name: lit.Type.Name, Ref: lit.Type}, []diag.Diagnostic{{
			Code:     "HZN1425",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown struct type %q", lit.Type.Name),
			Primary:  lit.Span,
		}}
	}
	seen := map[string]bool{}
	var diags []diag.Diagnostic
	for _, field := range lit.Fields {
		if seen[field.Name] {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1426",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("duplicate field %q in %s literal", field.Name, structDecl.Name),
				Primary:  field.Span,
			})
			continue
		}
		seen[field.Name] = true
		declField, ok := findField(structDecl, field.Name)
		if !ok {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1427",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("type %s has no field %q", structDecl.Name, field.Name),
				Primary:  field.Span,
			})
			continue
		}
		value, valueDiags := t.typeOf(field.Value)
		diags = append(diags, valueDiags...)
		fieldType := valueType{Name: declField.Type.Name, Ref: declField.Type}
		if isFixedArray(fieldType) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1433",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("fixed array field %s.%s cannot be set from a struct literal in Horizon v0", structDecl.Name, field.Name),
				Primary:  field.Span,
				Suggest:  "leave fixed array fields zeroed or populate them through compiler-known helpers",
			})
			continue
		}
		if isFixedArray(value) {
			diags = append(diags, fixedArrayValueDiagnostic(field.Span))
			continue
		}
		if !assignable(fieldType, value) {
			if d, ok := assignabilityDiagnostic(
				"HZN1428",
				fmt.Sprintf("cannot assign %s to field %s.%s (%s)", typeName(value), structDecl.Name, field.Name, typeName(fieldType)),
				fieldType,
				value,
				field.Value.GetSpan(),
			); ok {
				diags = append(diags, d)
			}
		}
	}
	return valueType{Name: structDecl.Name, Ref: lit.Type}, diags
}

func (t exprTyper) call(call ast.CallExpr) (valueType, []diag.Diagnostic) {
	var diags []diag.Diagnostic
	if name, ok := identCallTarget(call.Func); ok && isIntegerScalar(name) {
		return t.scalarConversion(name, call)
	}
	if name, ok := identCallTarget(call.Func); ok {
		if fn, found := t.funcs[name]; found {
			return t.userFunctionCall(fn, call)
		}
	}
	root, method, ok := selectorParts(call.Func)
	if !ok {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1410",
			Severity: diag.SeverityError,
			Message:  "only user helper, compiler-known helper, and map method calls are supported",
			Primary:  call.Span,
		}}
	}
	if root == "bpf" {
		return t.helperCall(method, call)
	}
	if root == "xdp" {
		return t.xdpCall(method, call)
	}
	if root == "tc" {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1453",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("tc.%s is not a callable helper in Horizon v0", method),
			Primary:  call.Span,
			Suggest:  "use named TC action constants such as tc.OK in return statements",
		}}
	}
	if root == "cgroup" {
		return t.cgroupCall(method, call)
	}
	if root == "lsm" {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1462",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("lsm.%s is not a callable helper in Horizon v0", method),
			Primary:  call.Span,
			Suggest:  "use named LSM action constants such as lsm.Allow in return statements",
		}}
	}
	if root == "kprobe" {
		return t.kprobeCall(method, call)
	}
	if root == "kretprobe" {
		return t.kretprobeCall(method, call)
	}
	if m, ok := t.maps[root]; ok {
		switch method {
		case "lookup":
			if len(call.Args) != 1 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".lookup", 1, len(call.Args)))
				return valueType{Name: m.Val.Name, Ref: m.Val, Ptr: true, MaybeNil: true}, diags
			}
			if !m.Kind.IsLookup() {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1418",
					Severity: diag.SeverityError,
					Message:  "lookup is only valid on keyed map kinds",
					Primary:  call.Span,
				})
			}
			arg, argDiags := t.typeOf(call.Args[0])
			diags = append(diags, argDiags...)
			keyType := valueType{Name: m.Key.Name, Ref: m.Key}
			if d, ok := assignabilityDiagnostic(
				"HZN1419",
				fmt.Sprintf("%s.lookup expects key %s, got %s", root, typeName(keyType), typeName(arg)),
				keyType,
				arg,
				call.Args[0].GetSpan(),
			); ok {
				diags = append(diags, d)
			}
			return valueType{Name: m.Val.Name, Ref: m.Val, Ptr: true, MaybeNil: true}, diags
		case "update":
			if len(call.Args) != 2 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".update", 2, len(call.Args)))
				return valueType{Name: "i64", Fallible: root + ".update"}, diags
			}
			if !m.Kind.IsLookup() {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1420",
					Severity: diag.SeverityError,
					Message:  "update is only valid on keyed map kinds",
					Primary:  call.Span,
				})
			}
			key, keyDiags := t.typeOf(call.Args[0])
			val, valDiags := t.typeOf(call.Args[1])
			diags = append(diags, keyDiags...)
			diags = append(diags, valDiags...)
			keyType := valueType{Name: m.Key.Name, Ref: m.Key}
			if d, ok := assignabilityDiagnostic(
				"HZN1421",
				fmt.Sprintf("%s.update expects key %s, got %s", root, typeName(keyType), typeName(key)),
				keyType,
				key,
				call.Args[0].GetSpan(),
			); ok {
				diags = append(diags, d)
			}
			valType := valueType{Name: m.Val.Name, Ref: m.Val}
			if d, ok := assignabilityDiagnostic(
				"HZN1422",
				fmt.Sprintf("%s.update expects value %s, got %s", root, typeName(valType), typeName(val)),
				valType,
				val,
				call.Args[1].GetSpan(),
			); ok {
				diags = append(diags, d)
			}
			return valueType{Name: "i64", Fallible: root + ".update"}, diags
		case "delete":
			if len(call.Args) != 1 {
				diags = append(diags, argCountDiagnostic(call.Span, root+".delete", 1, len(call.Args)))
				return valueType{Name: "i64", Fallible: root + ".delete"}, diags
			}
			if !m.Kind.IsHashLike() {
				diags = append(diags, diag.Diagnostic{
					Code:     "HZN1423",
					Severity: diag.SeverityError,
					Message:  "delete is only valid on hash-like map kinds",
					Primary:  call.Span,
				})
			}
			key, keyDiags := t.typeOf(call.Args[0])
			diags = append(diags, keyDiags...)
			keyType := valueType{Name: m.Key.Name, Ref: m.Key}
			if d, ok := assignabilityDiagnostic(
				"HZN1424",
				fmt.Sprintf("%s.delete expects key %s, got %s", root, typeName(keyType), typeName(key)),
				keyType,
				key,
				call.Args[0].GetSpan(),
			); ok {
				diags = append(diags, d)
			}
			return valueType{Name: "i64", Fallible: root + ".delete"}, diags
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
			arg, argDiags := t.typeOf(call.Args[0])
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

func (t exprTyper) userFunctionCall(fn ast.FuncDecl, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	if len(sectionAttrs(fn.Attrs)) != 0 {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1501",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("cannot call eBPF entrypoint function %q", fn.Name),
			Primary:  call.Span,
			Suggest:  "put reusable scalar logic in a sectionless helper function",
		}}
	}
	result := valueType{Name: fn.Return.Name, Ref: fn.Return, Ptr: fn.Return.Ptr}
	if len(call.Args) != len(fn.Params) {
		return result, []diag.Diagnostic{argCountDiagnostic(call.Span, fn.Name, len(fn.Params), len(call.Args))}
	}
	var diags []diag.Diagnostic
	for i, argExpr := range call.Args {
		arg, argDiags := t.typeOf(argExpr)
		diags = append(diags, argDiags...)
		param := fn.Params[i]
		paramType := valueType{Name: param.Type.Name, Ref: param.Type, Ptr: param.Type.Ptr}
		if d, ok := assignabilityDiagnostic(
			"HZN1502",
			fmt.Sprintf("%s argument %q expects %s, got %s", fn.Name, param.Name, typeName(paramType), typeName(arg)),
			paramType,
			arg,
			argExpr.GetSpan(),
		); ok {
			diags = append(diags, d)
		}
	}
	return result, diags
}

func (t exprTyper) scalarConversion(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	if len(call.Args) != 1 {
		return valueType{Name: name}, []diag.Diagnostic{argCountDiagnostic(call.Span, name, 1, len(call.Args))}
	}
	result := valueType{Name: name}
	arg, diags := t.typeOf(call.Args[0])
	if arg.IntLiteral != "" {
		result.IntLiteral = arg.IntLiteral
	}
	if valueKnownNonZero(arg) {
		result.NonZero = true
	}
	if valueKnownNonNegative(arg) || isUnsignedIntegerScalar(name) {
		result.NonNegative = true
	}
	result.MaxExclusive = arg.MaxExclusive
	if arg.Fallible != "" {
		diags = append(diags, fallibleResultDiagnostic(call.Span, arg.Fallible))
		return result, diags
	}
	if arg.Void || arg.Ptr || arg.MaybeNil || arg.Resource || !integerOperand(arg) ||
		arg.XDPAction || arg.TCAction || arg.CgroupAction || arg.LSMAction {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1463",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("cannot convert %s to %s", typeName(arg), name),
			Primary:  call.Span,
			Suggest:  "explicit conversions only work between integer scalar values, for example `u64(pid)`",
		})
		return result, diags
	}
	if d, ok := integerLiteralRangeDiagnostic(valueType{Name: name}, arg, call.Args[0].GetSpan()); ok {
		diags = append(diags, d)
	}
	return result, diags
}

func (t exprTyper) xdpCall(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	switch name {
	case "eth", "ipv4", "tcp", "udp":
		var header string
		switch name {
		case "eth":
			header = "xdp.Eth"
		case "ipv4":
			header = "xdp.IPv4"
		case "tcp":
			header = "xdp.TCP"
		case "udp":
			header = "xdp.UDP"
		}
		if len(call.Args) != 1 {
			return valueType{Name: header, Ptr: true, MaybeNil: true}, []diag.Diagnostic{argCountDiagnostic(call.Span, "xdp."+name, 1, len(call.Args))}
		}
		arg, diags := t.typeOf(call.Args[0])
		if !assignable(valueType{Name: "xdp.Context"}, arg) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1435",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("xdp.%s expects xdp.Context, got %s", name, typeName(arg)),
				Primary:  call.Span,
			})
		}
		return valueType{Name: header, Ptr: true, MaybeNil: true}, diags
	case "ntohs":
		if len(call.Args) != 1 {
			return valueType{Name: "u16"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "xdp.ntohs", 1, len(call.Args))}
		}
		arg, diags := t.typeOf(call.Args[0])
		target := valueType{Name: "u16"}
		if d, ok := assignabilityDiagnostic(
			"HZN1437",
			fmt.Sprintf("xdp.ntohs expects u16, got %s", typeName(arg)),
			target,
			arg,
			call.Args[0].GetSpan(),
		); ok {
			diags = append(diags, d)
		}
		return valueType{Name: "u16"}, diags
	default:
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1436",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown XDP packet helper xdp.%s", name),
			Primary:  call.Span,
			Suggest:  "use xdp.eth(ctx), xdp.ipv4(ctx), xdp.tcp(ctx), or xdp.udp(ctx)",
		}}
	}
}

func (t exprTyper) cgroupCall(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	switch name {
	case "family", "sock_type", "protocol", "dst_ip4", "src_ip4":
		return t.cgroupConnectFieldCall(name, call, "u32")
	case "dst_port":
		return t.cgroupConnectFieldCall(name, call, "u16")
	case "ip4":
		return t.cgroupIP4Call(call)
	default:
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1458",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown cgroup helper cgroup.%s", name),
			Primary:  call.Span,
			Suggest:  "use cgroup.family(ctx), cgroup.protocol(ctx), cgroup.dst_port(ctx), cgroup.dst_ip4(ctx), or named actions such as cgroup.Allow",
		}}
	}
}

func (t exprTyper) cgroupConnectFieldCall(name string, call ast.CallExpr, result string) (valueType, []diag.Diagnostic) {
	if len(call.Args) != 1 {
		return valueType{Name: result}, []diag.Diagnostic{argCountDiagnostic(call.Span, "cgroup."+name, 1, len(call.Args))}
	}
	arg, diags := t.typeOf(call.Args[0])
	if !assignable(valueType{Name: "cgroup.Connect"}, arg) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1457",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("cgroup.%s expects cgroup.Connect, got %s", name, typeName(arg)),
			Primary:  call.Span,
		})
	}
	return valueType{Name: result}, diags
}

func (t exprTyper) cgroupIP4Call(call ast.CallExpr) (valueType, []diag.Diagnostic) {
	if len(call.Args) != 4 {
		return valueType{Name: "u32"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "cgroup.ip4", 4, len(call.Args))}
	}
	var diags []diag.Diagnostic
	for _, argExpr := range call.Args {
		arg, argDiags := t.typeOf(argExpr)
		diags = append(diags, argDiags...)
		if !assignable(valueType{Name: "u8"}, arg) {
			if d, ok := cgroupIP4OctetRangeDiagnostic(arg, argExpr.GetSpan()); ok {
				diags = append(diags, d)
				continue
			}
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1468",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("cgroup.ip4 octets must be u8-compatible integers, got %s", typeName(arg)),
				Primary:  argExpr.GetSpan(),
			})
			continue
		}
	}
	return valueType{Name: "u32"}, diags
}

func (t exprTyper) kprobeCall(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	if !isKprobeArgHelper(name) {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1464",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown kprobe helper kprobe.%s", name),
			Primary:  call.Span,
			Suggest:  "use kprobe.arg1(ctx) through kprobe.arg5(ctx) for typed register arguments",
		}}
	}
	if len(call.Args) != 1 {
		return valueType{Name: "u64"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "kprobe."+name, 1, len(call.Args))}
	}
	arg, diags := t.typeOf(call.Args[0])
	if !assignable(valueType{Name: "kprobe.Context"}, arg) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1465",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("kprobe.%s expects kprobe.Context, got %s", name, typeName(arg)),
			Primary:  call.Span,
		})
	}
	return valueType{Name: "u64"}, diags
}

func (t exprTyper) kretprobeCall(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	if name != "ret" {
		return valueType{}, []diag.Diagnostic{{
			Code:     "HZN1466",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unknown kretprobe helper kretprobe.%s", name),
			Primary:  call.Span,
			Suggest:  "use kretprobe.ret(ctx) for the typed return register value",
		}}
	}
	if len(call.Args) != 1 {
		return valueType{Name: "i64"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "kretprobe.ret", 1, len(call.Args))}
	}
	arg, diags := t.typeOf(call.Args[0])
	if !assignable(valueType{Name: "kretprobe.Context"}, arg) {
		diags = append(diags, diag.Diagnostic{
			Code:     "HZN1467",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("kretprobe.ret expects kretprobe.Context, got %s", typeName(arg)),
			Primary:  call.Span,
		})
	}
	return valueType{Name: "i64"}, diags
}

func (t exprTyper) helperCall(name string, call ast.CallExpr) (valueType, []diag.Diagnostic) {
	switch name {
	case "current_pid", "current_ppid", "current_uid":
		if len(call.Args) != 0 {
			return valueType{Name: "u32"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf."+name, 0, len(call.Args))}
		}
		return valueType{Name: "u32"}, nil
	case "ktime_get_ns":
		if len(call.Args) != 0 {
			return valueType{Name: "u64"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf.ktime_get_ns", 0, len(call.Args))}
		}
		return valueType{Name: "u64"}, nil
	case "current_comm":
		if len(call.Args) != 1 {
			return valueType{Void: true}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf.current_comm", 1, len(call.Args))}
		}
		arg, diags := t.typeOf(call.Args[0])
		if !arg.Ptr || arg.Ref.Len != "16" || arg.Ref.Elem == nil || arg.Ref.Elem.Name != "u8" {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1415",
				Severity: diag.SeverityError,
				Message:  "bpf.current_comm expects a pointer to [16]u8",
				Primary:  call.Span,
			})
		}
		return valueType{Void: true}, diags
	case "probe_read_user_str":
		if len(call.Args) != 2 {
			return valueType{Name: "i64", Fallible: "bpf.probe_read_user_str"}, []diag.Diagnostic{argCountDiagnostic(call.Span, "bpf.probe_read_user_str", 2, len(call.Args))}
		}
		dst, dstDiags := t.typeOf(call.Args[0])
		ptr, ptrDiags := t.typeOf(call.Args[1])
		diags := append(dstDiags, ptrDiags...)
		if !dst.Ptr || !isU8FixedArray(dst) {
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN1474",
				Severity: diag.SeverityError,
				Message:  "bpf.probe_read_user_str expects a pointer to a fixed [N]u8 destination",
				Primary:  call.Args[0].GetSpan(),
				Suggest:  "declare a fixed byte array field such as `path [256]u8` and pass `&event.path`",
			})
		}
		if d, ok := assignabilityDiagnostic(
			"HZN1475",
			fmt.Sprintf("bpf.probe_read_user_str expects a u64 user pointer, got %s", typeName(ptr)),
			valueType{Name: "u64"},
			ptr,
			call.Args[1].GetSpan(),
		); ok {
			diags = append(diags, d)
		}
		return valueType{Name: "i64", Fallible: "bpf.probe_read_user_str"}, diags
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

func identCallTarget(expr ast.Expr) (string, bool) {
	ident, ok := expr.(ast.IdentExpr)
	if !ok {
		return "", false
	}
	return ident.Name, ident.Name != ""
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
		return isIntegerScalar(dst.Name) && (src.IntLiteral == "" || integerLiteralFitsScalar(src.IntLiteral, dst.Name))
	}
	if src.Name == "nil" {
		return dst.Ptr || dst.MaybeNil
	}
	if dst.Ptr != src.Ptr {
		return false
	}
	if dst.Ref.Len != "" || src.Ref.Len != "" {
		return false
	}
	return dst.Name == src.Name
}

func assignabilityDiagnostic(code string, message string, dst valueType, src valueType, primary span.Span) (diag.Diagnostic, bool) {
	if assignable(dst, src) {
		return diag.Diagnostic{}, false
	}
	if d, ok := integerLiteralRangeDiagnostic(dst, src, primary); ok {
		return d, true
	}
	return diag.Diagnostic{
		Code:     code,
		Severity: diag.SeverityError,
		Message:  message,
		Primary:  primary,
	}, true
}

func integerOperandRangeDiagnostic(expr ast.BinaryExpr, left valueType, right valueType) (diag.Diagnostic, bool) {
	if left.Name != "untyped_int" && right.Name == "untyped_int" {
		return integerLiteralRangeDiagnostic(left, right, expr.Right.GetSpan())
	}
	if right.Name != "untyped_int" && left.Name == "untyped_int" {
		return integerLiteralRangeDiagnostic(right, left, expr.Left.GetSpan())
	}
	return diag.Diagnostic{}, false
}

func integerLiteralRangeDiagnostic(dst valueType, src valueType, primary span.Span) (diag.Diagnostic, bool) {
	if src.IntLiteral == "" || !integerOperand(src) || !isIntegerScalar(dst.Name) || integerLiteralFitsScalar(src.IntLiteral, dst.Name) {
		return diag.Diagnostic{}, false
	}
	return diag.Diagnostic{
		Code:     "HZN1470",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("integer literal %s is outside range for %s", src.IntLiteral, dst.Name),
		Primary:  primary,
		Suggest:  fmt.Sprintf("use a literal in %s or choose a wider scalar type", integerScalarBounds(dst.Name)),
	}, true
}

func cgroupIP4OctetRangeDiagnostic(src valueType, primary span.Span) (diag.Diagnostic, bool) {
	if src.Name != "untyped_int" || src.IntLiteral == "" || integerLiteralFitsScalar(src.IntLiteral, "u8") {
		return diag.Diagnostic{}, false
	}
	return diag.Diagnostic{
		Code:     "HZN1469",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("cgroup.ip4 octet %q is outside 0..255", src.IntLiteral),
		Primary:  primary,
	}, true
}

func integerLiteralFitsScalar(lit string, scalar string) bool {
	switch scalar {
	case "u8":
		return unsignedLiteralFits(lit, 255)
	case "u16":
		return unsignedLiteralFits(lit, 65535)
	case "u32":
		return unsignedLiteralFits(lit, 4294967295)
	case "u64":
		return unsignedLiteralFits(lit, ^uint64(0))
	case "i8":
		return signedLiteralFits(lit, -128, 127)
	case "i16":
		return signedLiteralFits(lit, -32768, 32767)
	case "i32":
		return signedLiteralFits(lit, -2147483648, 2147483647)
	case "i64":
		return signedLiteralFits(lit, -9223372036854775808, 9223372036854775807)
	default:
		return false
	}
}

func integerLiteralBig(t valueType) (*big.Int, bool) {
	if t.IntLiteral == "" {
		return nil, false
	}
	value, ok := new(big.Int).SetString(t.IntLiteral, 0)
	if !ok {
		return nil, false
	}
	return value, true
}

func literalZero(lit string) bool {
	value, ok := new(big.Int).SetString(lit, 0)
	return ok && value.Sign() == 0
}

func literalNonZero(lit string) bool {
	value, ok := new(big.Int).SetString(lit, 0)
	return ok && value.Sign() != 0
}

func literalNonNegative(lit string) bool {
	value, ok := new(big.Int).SetString(lit, 0)
	return ok && value.Sign() >= 0
}

func literalInt(lit string) (int, bool) {
	value, ok := new(big.Int).SetString(lit, 0)
	if !ok || !value.IsInt64() {
		return 0, false
	}
	asInt64 := value.Int64()
	asInt := int(asInt64)
	if int64(asInt) != asInt64 {
		return 0, false
	}
	return asInt, true
}

func valueKnownNonZero(t valueType) bool {
	if t.IntLiteral != "" {
		return literalNonZero(t.IntLiteral)
	}
	return t.NonZero
}

func valueKnownNonNegative(t valueType) bool {
	if t.IntLiteral != "" {
		return literalNonNegative(t.IntLiteral)
	}
	return t.NonNegative || isUnsignedIntegerScalar(t.Name)
}

func integerBitWidth(name string) int {
	switch name {
	case "u8", "i8":
		return 8
	case "u16", "i16":
		return 16
	case "u32", "i32":
		return 32
	case "u64", "i64", "untyped_int":
		return 64
	default:
		return 0
	}
}

func integerScalarBounds(scalar string) string {
	switch scalar {
	case "u8":
		return "0..255"
	case "u16":
		return "0..65535"
	case "u32":
		return "0..4294967295"
	case "u64":
		return "0..18446744073709551615"
	case "i8":
		return "-128..127"
	case "i16":
		return "-32768..32767"
	case "i32":
		return "-2147483648..2147483647"
	case "i64":
		return "-9223372036854775808..9223372036854775807"
	default:
		return "the scalar range"
	}
}

func unsignedLiteralFits(lit string, max uint64) bool {
	value, err := strconv.ParseUint(lit, 0, 64)
	if err != nil {
		return false
	}
	return value <= max
}

func signedLiteralFits(lit string, min int64, max int64) bool {
	value, err := strconv.ParseInt(lit, 0, 64)
	if err != nil {
		return false
	}
	return value >= min && value <= max
}

func negateIntegerLiteral(lit string) string {
	if lit == "" || lit == "0" {
		return lit
	}
	if strings.HasPrefix(lit, "-") {
		return strings.TrimPrefix(lit, "-")
	}
	return "-" + lit
}

func isFixedArray(t valueType) bool {
	return t.Ref.Len != "" && t.Ref.Elem != nil
}

func isU8FixedArray(t valueType) bool {
	return t.Ref.Len != "" && t.Ref.Elem != nil && t.Ref.Elem.Name == "u8"
}

func isTrackedPointer(t valueType) bool {
	return t.MaybeNil || t.Resource
}

func directTrackedPointerSource(expr ast.Expr, maps map[string]ast.MapDecl) bool {
	call, ok := expr.(ast.CallExpr)
	if !ok {
		return false
	}
	root, method, ok := selectorParts(call.Func)
	if !ok {
		return false
	}
	if root == "xdp" {
		return isXDPPacketHeaderHelper(method)
	}
	m, ok := maps[root]
	if !ok {
		return false
	}
	switch method {
	case "lookup":
		return m.Kind.IsLookup()
	case "reserve":
		return m.Kind == ast.MapKindRingbuf
	default:
		return false
	}
}

func isXDPPacketHeaderHelper(name string) bool {
	switch name {
	case "eth", "ipv4", "tcp", "udp":
		return true
	default:
		return false
	}
}

func trackedPointerAliasDiagnostic(primary span.Span, name string, typ valueType) diag.Diagnostic {
	target := "tracked pointer result"
	if name != "" {
		target = fmt.Sprintf("local %q", name)
	}
	return diag.Diagnostic{
		Code:     "HZN1447",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("%s cannot copy or alias a %s", target, trackedPointerKind(typ)),
		Primary:  primary,
		Suggest:  "bind lookup, reserve, and packet header results directly once, nil-check that binding, and use that same name",
	}
}

func trackedPointerKind(typ valueType) string {
	if typ.Resource {
		return "ringbuf reservation"
	}
	switch typ.Name {
	case "xdp.Eth", "xdp.IPv4", "xdp.TCP", "xdp.UDP":
		return "packet header pointer"
	default:
		return "map lookup pointer"
	}
}

func fixedArrayLocalDiagnostic(primary span.Span, name string, typ valueType) diag.Diagnostic {
	message := fmt.Sprintf("fixed array values cannot be stored in local %q in Horizon v0", name)
	if typ.Ptr {
		message = fmt.Sprintf("fixed array addresses cannot be stored in local %q in Horizon v0", name)
	}
	return diag.Diagnostic{
		Code:     "HZN1430",
		Severity: diag.SeverityError,
		Message:  message,
		Primary:  primary,
		Suggest:  "pass a field address such as &event.comm directly to a compiler-known helper instead of copying or aliasing the array",
	}
}

func fixedArrayValueDiagnostic(primary span.Span) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN1430",
		Severity: diag.SeverityError,
		Message:  "fixed array values are address-only in Horizon v0",
		Primary:  primary,
		Suggest:  "pass a field address such as &event.comm directly to a compiler-known helper instead of copying the array",
	}
}

func fallibleResultDiagnostic(primary span.Span, operation string) diag.Diagnostic {
	if operation == "" {
		operation = "map operation"
	}
	return diag.Diagnostic{
		Code:     "HZN1446",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("fallible %s result must be checked with a direct comparison", operation),
		Primary:  primary,
		Suggest:  fmt.Sprintf("compare the result explicitly, for example `if %s(...) != 0 { return 0 }`", operation),
	}
}

func xdpSelectorType(name string) (valueType, bool) {
	switch name {
	case "Aborted", "Drop", "Pass", "Tx", "Redirect":
		return valueType{Name: "i32", XDPAction: true}, true
	case "EtherTypeIPv4":
		return valueType{Name: "u16"}, true
	case "IPProtoICMP", "IPProtoTCP", "IPProtoUDP":
		return valueType{Name: "u8"}, true
	default:
		return valueType{}, false
	}
}

func tcSelectorType(name string) (valueType, bool) {
	switch name {
	case "OK", "Reclassify", "Shot", "Pipe", "Stolen", "Redirect":
		return valueType{Name: "i32", TCAction: true}, true
	default:
		return valueType{}, false
	}
}

func cgroupSelectorType(name string) (valueType, bool) {
	switch name {
	case "Allow", "Deny":
		return valueType{Name: "i32", CgroupAction: true}, true
	case "FamilyIPv4", "FamilyIPv6", "SockStream", "SockDgram", "ProtocolTCP", "ProtocolUDP":
		return valueType{Name: "u32"}, true
	default:
		return valueType{}, false
	}
}

func lsmSelectorType(name string) (valueType, bool) {
	switch name {
	case "Allow", "Deny":
		return valueType{Name: "i32", LSMAction: true}, true
	default:
		return valueType{}, false
	}
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

func isUnsignedIntegerScalar(name string) bool {
	switch name {
	case "u8", "u16", "u32", "u64":
		return true
	default:
		return false
	}
}

func isSignedIntegerScalar(name string) bool {
	switch name {
	case "i8", "i16", "i32", "i64":
		return true
	default:
		return false
	}
}

func isKprobeArgHelper(name string) bool {
	switch name {
	case "arg1", "arg2", "arg3", "arg4", "arg5":
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
	if t.XDPAction {
		return "xdp action"
	}
	if t.TCAction {
		return "tc action"
	}
	if t.CgroupAction {
		return "cgroup action"
	}
	if t.LSMAction {
		return "lsm action"
	}
	if t.Ref.Len != "" && t.Ref.Elem != nil {
		name = "[" + t.Ref.Len + "]" + t.Ref.Elem.Name
	}
	if t.Ptr {
		return "*" + name
	}
	return name
}

func attrStringArg(attr ast.Attr) string {
	if len(attr.Args) == 0 {
		return ""
	}
	if value, ok := attr.Args[0].(ast.StringExpr); ok {
		return value.Value
	}
	return ""
}

func attrHasStringArg(attr ast.Attr) bool {
	if len(attr.Args) != 1 {
		return false
	}
	_, ok := attr.Args[0].(ast.StringExpr)
	return ok
}

func argCountDiagnostic(primary span.Span, name string, want, got int) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN1417",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("%s expects %d argument(s), got %d", name, want, got),
		Primary:  primary,
	}
}
