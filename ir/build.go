package ir

import (
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func FromAST(file ast.File) (Program, []diag.Diagnostic) {
	program := Program{Package: file.Package}
	var diags []diag.Diagnostic
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			program.Structs = append(program.Structs, buildStruct(d))
		case ast.MapDecl:
			program.Maps = append(program.Maps, buildMap(d))
		case ast.FuncDecl:
			fn := buildFunction(d)
			program.Functions = append(program.Functions, fn)
			program.Capabilities = append(program.Capabilities, buildCapabilities(d, fn, program.Maps)...)
		}
	}
	return program, diags
}

func Merge(programs ...Program) Program {
	var merged Program
	for _, program := range programs {
		if merged.Package == "" {
			merged.Package = program.Package
		}
		merged.Structs = append(merged.Structs, program.Structs...)
		merged.Functions = append(merged.Functions, program.Functions...)
		merged.Maps = append(merged.Maps, program.Maps...)
		merged.Capabilities = append(merged.Capabilities, program.Capabilities...)
		merged.SourceMap.Mappings = append(merged.SourceMap.Mappings, program.SourceMap.Mappings...)
	}
	return merged
}

func buildStruct(decl ast.TypeDecl) Struct {
	out := Struct{Name: decl.Name, Span: decl.Span}
	for _, field := range decl.Fields {
		out.Fields = append(out.Fields, Field{
			Name: field.Name,
			Type: buildType(field.Type),
			Span: field.Span,
		})
	}
	return out
}

func buildMap(decl ast.MapDecl) Map {
	return Map{
		Name: decl.Name,
		Kind: MapKind(decl.Kind),
		Key:  buildType(decl.Key),
		Val:  buildType(decl.Val),
	}
}

func buildFunction(decl ast.FuncDecl) Function {
	fn := Function{
		Name:     decl.Name,
		Section:  sectionFromAttrs(decl.Attrs),
		Return:   buildType(decl.Return),
		BodyText: decl.BodyText,
		Span:     decl.Span,
	}
	for _, param := range decl.Params {
		fn.Params = append(fn.Params, Param{Name: param.Name, Type: buildType(param.Type)})
	}
	var block Block
	for _, stmt := range decl.Body {
		if raw, ok := stmt.(ast.RawStmt); ok {
			block.Statements = append(block.Statements, Statement{
				Kind: "raw",
				Text: raw.Text,
				Span: raw.Span,
			})
		}
	}
	if len(block.Statements) > 0 {
		fn.Body = append(fn.Body, block)
	}
	return fn
}

func buildCapabilities(decl ast.FuncDecl, fn Function, maps []Map) []Capability {
	var out []Capability
	for _, attr := range decl.Attrs {
		if attr.Name != "capability" {
			continue
		}
		name := stringArg(attr)
		events, emits := eventMaps(fn.BodyText, maps)
		out = append(out, Capability{
			Name:    name,
			Kind:    CapabilitySource,
			Program: fn.Name,
			Section: manifestSection(fn.Section),
			Emits:   emits,
			Maps: CapabilityMapAccess{
				Read:   []string{},
				Write:  []string{},
				Events: events,
			},
			Danger: DangerObserve,
		})
	}
	return out
}

func buildType(ref ast.TypeRef) Type {
	typ := Type{
		Name: ref.Name,
		Len:  ref.Len,
		Ptr:  ref.Ptr,
	}
	for _, arg := range ref.Args {
		typ.Args = append(typ.Args, buildType(arg))
	}
	if ref.Elem != nil {
		elem := buildType(*ref.Elem)
		typ.Elem = &elem
	}
	return typ
}

func sectionFromAttrs(attrs []ast.Attr) Section {
	for _, attr := range attrs {
		if attr.Name != "tracepoint" {
			continue
		}
		attach := stringArg(attr)
		return Section{
			Kind:   ProgramTracepoint,
			Attach: attach,
			Name:   "tracepoint/" + strings.ReplaceAll(attach, ":", "/"),
		}
	}
	return Section{}
}

func stringArg(attr ast.Attr) string {
	if len(attr.Args) == 0 {
		return ""
	}
	if value, ok := attr.Args[0].(ast.StringExpr); ok {
		return value.Value
	}
	return ""
}

func eventMaps(body string, maps []Map) ([]string, string) {
	var events []string
	emits := ""
	for _, m := range maps {
		if m.Kind != MapKindRingbuf {
			continue
		}
		if !strings.Contains(body, m.Name+".submit(") {
			continue
		}
		events = append(events, m.Name)
		if emits == "" {
			emits = m.Val.Name
		}
	}
	return events, emits
}

func manifestSection(section Section) string {
	if section.Kind == ProgramTracepoint && section.Attach != "" {
		return "tracepoint/" + section.Attach
	}
	return section.Name
}
