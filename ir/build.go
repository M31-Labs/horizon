package ir

import (
	"strings"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

func FromAST(file ast.File) (Program, []diag.Diagnostic) {
	program := Program{Package: file.Package}
	var diags []diag.Diagnostic
	aliases := typeAliases(file)
	type functionDecl struct {
		Decl ast.FuncDecl
		Func Function
	}
	var funcs []functionDecl
	capabilityAliases := map[string]capabilityAlias{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			if d.IsAlias() {
				continue
			}
			program.Structs = append(program.Structs, buildStruct(d, aliases))
		case ast.TypeGroupDecl:
			program.Structs = append(program.Structs, buildStructGroup(d, aliases)...)
		case ast.ConstDecl:
			program.Constants = append(program.Constants, buildConst(d, aliases))
		case ast.ConstGroupDecl:
			program.Constants = append(program.Constants, buildConstGroup(d, aliases)...)
		case ast.EnumDecl:
			program.Constants = append(program.Constants, buildEnumConsts(d, aliases)...)
		case ast.CapabilityDecl:
			level := DangerLevel(d.Danger)
			capabilityAliases[d.Name] = capabilityAlias{
				Name:   d.Value,
				Danger: level,
				Axes:   dangerAxesFromString(d.Danger, level),
			}
		case ast.MapDecl:
			program.Maps = append(program.Maps, buildMap(d, aliases))
		case ast.FuncDecl:
			funcs = append(funcs, functionDecl{
				Decl: d,
				Func: buildFunction(d, aliases),
			})
		}
	}
	for _, fn := range funcs {
		program.Functions = append(program.Functions, fn.Func)
		program.Capabilities = append(program.Capabilities, buildCapabilities(fn.Decl, fn.Func, program.Maps, capabilityAliases)...)
	}
	return program, diags
}

func typeAliases(file ast.File) map[string]ast.TypeRef {
	aliases := map[string]ast.TypeRef{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case ast.TypeDecl:
			if d.IsAlias() && d.Name != "" {
				aliases[d.Name] = d.Alias
			}
		case ast.TypeGroupDecl:
			for _, typeDecl := range d.Types {
				if typeDecl.IsAlias() && typeDecl.Name != "" {
					aliases[typeDecl.Name] = typeDecl.Alias
				}
			}
		}
	}
	return aliases
}

func Merge(programs ...Program) Program {
	var merged Program
	for _, program := range programs {
		if merged.Package == "" {
			merged.Package = program.Package
		}
		merged.Structs = append(merged.Structs, program.Structs...)
		merged.Constants = append(merged.Constants, program.Constants...)
		merged.Functions = append(merged.Functions, program.Functions...)
		merged.Maps = append(merged.Maps, program.Maps...)
		merged.Capabilities = append(merged.Capabilities, program.Capabilities...)
	}
	merged.Capabilities = refreshCapabilityAccesses(merged)
	return merged
}

func refreshCapabilityAccesses(program Program) []Capability {
	if len(program.Capabilities) == 0 {
		return nil
	}
	functions := map[string]Function{}
	for _, fn := range program.Functions {
		functions[fn.Name] = fn
	}
	out := make([]Capability, 0, len(program.Capabilities))
	for _, cap := range program.Capabilities {
		if fn, ok := functions[cap.Program]; ok {
			access := mapAccesses(fn, program.Maps)
			cap.Maps = access.Maps
			cap.Emits = access.Emits
			if cap.Section == "" {
				cap.Section = fn.Section.ManifestName()
			}
			if cap.Danger == "" {
				cap.Danger = inferDanger(fn)
			}
		}
		out = append(out, cap)
	}
	return out
}

func buildConst(decl ast.ConstDecl, aliases map[string]ast.TypeRef) Const {
	return Const{
		Name:  decl.Name,
		Type:  buildType(decl.Type, aliases),
		Value: buildExpr(decl.Value),
		Span:  decl.Span,
	}
}

func buildConstGroup(decl ast.ConstGroupDecl, aliases map[string]ast.TypeRef) []Const {
	out := make([]Const, 0, len(decl.Consts))
	for _, constant := range decl.Consts {
		out = append(out, buildConst(constant, aliases))
	}
	return out
}

func buildEnumConsts(decl ast.EnumDecl, aliases map[string]ast.TypeRef) []Const {
	out := make([]Const, 0, len(decl.Values))
	for _, value := range decl.Values {
		out = append(out, Const{
			Name:  value.Name,
			Type:  buildType(decl.Type, aliases),
			Value: buildExpr(value.Value),
			Span:  value.Span,
		})
	}
	return out
}

func buildStruct(decl ast.TypeDecl, aliases map[string]ast.TypeRef) Struct {
	out := Struct{Name: decl.Name, Span: decl.Span}
	for _, field := range decl.Fields {
		out.Fields = append(out.Fields, Field{
			Name: field.Name,
			Type: buildType(field.Type, aliases),
			Span: field.Span,
		})
	}
	return out
}

func buildStructGroup(decl ast.TypeGroupDecl, aliases map[string]ast.TypeRef) []Struct {
	out := make([]Struct, 0, len(decl.Types))
	for _, typ := range decl.Types {
		if typ.IsAlias() {
			continue
		}
		out = append(out, buildStruct(typ, aliases))
	}
	return out
}

func buildMap(decl ast.MapDecl, aliases map[string]ast.TypeRef) Map {
	return Map{
		Name:               decl.Name,
		Kind:               MapKind(decl.Kind),
		Key:                buildType(decl.Key, aliases),
		Val:                buildType(decl.Val, aliases),
		MaxEntries:         decl.MaxEntries,
		SteadyStateEntries: decl.SteadyStateEntries,
		AccessFreq:         decl.AccessFreq,
		Span:               decl.Span,
	}
}

func buildFunction(decl ast.FuncDecl, aliases map[string]ast.TypeRef) Function {
	fn := Function{
		Name:     decl.Name,
		Section:  sectionFromAttrs(decl.Attrs),
		Return:   buildType(decl.Return, aliases),
		BodyText: decl.BodyText,
		Span:     decl.Span,
	}
	for _, param := range decl.Params {
		typ := buildType(param.Type, aliases)
		fn.Params = append(fn.Params, Param{
			Name:     param.Name,
			Type:     typ,
			Resource: isResourceParamType(typ),
		})
	}
	var block Block
	for _, stmt := range decl.Body {
		block.Statements = append(block.Statements, buildStatement(stmt, aliases))
	}
	if len(block.Statements) > 0 {
		fn.Body = append(fn.Body, block)
	}
	return fn
}

func buildStatement(stmt ast.Stmt, aliases map[string]ast.TypeRef) Statement {
	switch s := stmt.(type) {
	case ast.ShortVarStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "short_var", Name: s.Name, Value: &value, Span: s.Span}
	case ast.VarDeclStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "var_decl", Name: s.Name, Type: buildType(s.Type, aliases), Value: &value, Span: s.Span}
	case ast.AssignStmt:
		target := buildExpr(s.Target)
		value := buildExpr(s.Value)
		return Statement{Kind: "assign", Target: &target, Value: &value, Span: s.Span}
	case ast.ReturnStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "return", Value: &value, Span: s.Span}
	case ast.IfStmt:
		init := buildStatementPtr(s.Init, aliases)
		cond := buildExpr(s.Cond)
		return Statement{Kind: "if", Init: init, Cond: &cond, Then: buildStatements(s.Then, aliases), Else: buildStatements(s.Else, aliases), Span: s.Span}
	case ast.ForStmt:
		init := buildStatementPtr(s.Init, aliases)
		cond := buildExpr(s.Cond)
		post := buildStatementPtr(s.Post, aliases)
		return Statement{Kind: "for", Init: init, Cond: &cond, Post: post, Body: buildStatements(s.Body, aliases), Span: s.Span}
	case ast.SwitchStmt:
		value := buildExpr(s.Value)
		return Statement{Kind: "switch", Value: &value, Cases: buildSwitchCases(s.Cases, aliases), Span: s.Span}
	case ast.ExprStmt:
		expr := buildExpr(s.Expr)
		return Statement{Kind: "expr", Expr: &expr, Span: s.Span}
	case ast.IncStmt:
		return Statement{Kind: "inc", Name: s.Name, Op: s.Op, Span: s.Span}
	case ast.RawStmt:
		return Statement{Kind: "raw", Value: &Expr{Kind: "raw", Value: s.Text, Span: s.Span}, Span: s.Span}
	default:
		return Statement{Kind: "unknown", Span: stmt.GetSpan()}
	}
}

func buildStatementPtr(stmt ast.Stmt, aliases map[string]ast.TypeRef) *Statement {
	if stmt == nil {
		return nil
	}
	built := buildStatement(stmt, aliases)
	return &built
}

func buildStatements(stmts []ast.Stmt, aliases map[string]ast.TypeRef) []Statement {
	out := make([]Statement, 0, len(stmts))
	for _, stmt := range stmts {
		out = append(out, buildStatement(stmt, aliases))
	}
	return out
}

func buildSwitchCases(cases []ast.SwitchCase, aliases map[string]ast.TypeRef) []SwitchCase {
	out := make([]SwitchCase, 0, len(cases))
	for _, c := range cases {
		out = append(out, SwitchCase{
			Values:  buildExprs(c.Values),
			Body:    buildStatements(c.Body, aliases),
			Default: c.Default,
			Span:    c.Span,
		})
	}
	return out
}

func buildExpr(expr ast.Expr) Expr {
	switch e := expr.(type) {
	case nil:
		return Expr{}
	case ast.IdentExpr:
		return Expr{Kind: "ident", Name: e.Name, Span: e.Span}
	case ast.SelectorExpr:
		operand := buildExpr(e.Operand)
		return Expr{Kind: "selector", Operand: &operand, Field: e.Field, Span: e.Span}
	case ast.CallExpr:
		fn := buildExpr(e.Func)
		return Expr{Kind: "call", Func: &fn, Args: buildExprs(e.Args), Span: e.Span}
	case ast.StructLiteralExpr:
		return Expr{Kind: "struct_lit", Name: e.Type.Name, Fields: buildExprFields(e.Fields), Span: e.Span}
	case ast.UnaryExpr:
		operand := buildExpr(e.Expr)
		return Expr{Kind: "unary", Op: e.Op, Operand: &operand, Span: e.Span}
	case ast.BinaryExpr:
		left := buildExpr(e.Left)
		right := buildExpr(e.Right)
		return Expr{Kind: "binary", Op: e.Op, Left: &left, Right: &right, Span: e.Span}
	case ast.IntExpr:
		return Expr{Kind: "int", Value: e.Value, Span: e.Span}
	case ast.BoolExpr:
		if e.Value {
			return Expr{Kind: "bool", Value: "true", Span: e.Span}
		}
		return Expr{Kind: "bool", Value: "false", Span: e.Span}
	case ast.NilExpr:
		return Expr{Kind: "nil", Span: e.Span}
	case ast.RawExpr:
		return Expr{Kind: "raw", Value: e.Text, Span: e.Span}
	case ast.StringExpr:
		return Expr{Kind: "string", Value: e.Value, Span: e.Span}
	default:
		return Expr{Kind: "unknown", Span: expr.GetSpan()}
	}
}

func buildExprFields(fields []ast.StructLiteralField) []ExprField {
	out := make([]ExprField, 0, len(fields))
	for _, field := range fields {
		out = append(out, ExprField{
			Name:  field.Name,
			Value: buildExpr(field.Value),
			Span:  field.Span,
		})
	}
	return out
}

func buildExprs(exprs []ast.Expr) []Expr {
	out := make([]Expr, 0, len(exprs))
	for _, expr := range exprs {
		out = append(out, buildExpr(expr))
	}
	return out
}

type capabilityAlias struct {
	Name   string
	Danger DangerLevel
	Axes   DangerAxes // additive: axes computed from the declared danger string
	// Origin records the import alias of the package this capability was
	// declared in, when the capability is referenced via a qualified
	// `<alias>.<Name>` SelectorExpr in an attribute (roadmap #20 — Phase
	// 2 Subtask 3c). Local capabilities have Origin == "". Task 5 (cross-
	// package aggregation) consumes Origin when emitting the manifest.
	Origin string
}

func buildCapabilities(decl ast.FuncDecl, fn Function, maps []Map, capabilityAliases map[string]capabilityAlias) []Capability {
	var out []Capability
	for _, attr := range decl.Attrs {
		if attr.Name != "capability" {
			continue
		}
		name, danger, _ := capabilityArgWithAxes(attr, capabilityAliases)
		floor := moreDangerous(inferDanger(fn), capabilityNameDanger(name))
		danger = declaredDanger(danger, floor)
		// Always derive axes from the final (possibly raised) danger level.
		// Axes from the alias declaration are discarded if danger was raised,
		// because stale axes would misrepresent the effective capability risk.
		axes := danger.Axes()
		access := mapAccesses(fn, maps)
		out = append(out, Capability{
			Name:    name,
			Kind:    CapabilitySource,
			Program: fn.Name,
			Section: fn.Section.ManifestName(),
			Emits:   access.Emits,
			Maps:    access.Maps,
			Danger:  danger,
			Axes:    axes,
			Span:    attr.Span,
		})
	}
	return out
}

// dangerAxesFromString computes DangerAxes from a raw danger string. If the
// string contains a comma, it is parsed as an explicit "mode,scope,reversibility"
// triple. Otherwise, it falls back to DangerLevel.Axes() migration table.
// Malformed triple strings return the zero DangerAxes (validation at type-check
// time already caught and reported the error via ParseDangerAxes in types/).
func dangerAxesFromString(s string, level DangerLevel) DangerAxes {
	if strings.ContainsRune(s, ',') {
		parts := strings.SplitN(s, ",", 3)
		if len(parts) == 3 {
			return DangerAxes{
				Mode:          strings.TrimSpace(parts[0]),
				Scope:         strings.TrimSpace(parts[1]),
				Reversibility: strings.TrimSpace(parts[2]),
			}
		}
	}
	return level.Axes()
}

func buildType(ref ast.TypeRef, aliases map[string]ast.TypeRef) Type {
	ref = resolveAliasTypeRef(ref, aliases, map[string]bool{})
	typ := Type{
		Name: ref.Name,
		Len:  ref.Len,
		Ptr:  ref.Ptr,
	}
	for _, arg := range ref.Args {
		typ.Args = append(typ.Args, buildType(arg, aliases))
	}
	if ref.Elem != nil {
		elem := buildType(*ref.Elem, aliases)
		typ.Elem = &elem
	}
	return typ
}

// isResourceParamType reports whether a function parameter type carries a
// tracked nullable resource handle (e.g. *Event, *Counter, *xdp.Eth). The
// matching predicate in types/checker.go (helperResourceParamType) runs against
// ast.TypeRef and must classify the same set of params as resources.
func isResourceParamType(typ Type) bool {
	if !typ.Ptr {
		return false
	}
	if typ.Len != "" {
		return false
	}
	switch typ.Name {
	case "", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool":
		return false
	}
	return true
}

func resolveAliasTypeRef(ref ast.TypeRef, aliases map[string]ast.TypeRef, visiting map[string]bool) ast.TypeRef {
	if ref.IsZero() {
		return ref
	}
	for i := range ref.Args {
		ref.Args[i] = resolveAliasTypeRef(ref.Args[i], aliases, visiting)
	}
	if ref.Elem != nil {
		elem := resolveAliasTypeRef(*ref.Elem, aliases, visiting)
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
	resolved := resolveAliasTypeRef(alias, aliases, visiting)
	delete(visiting, ref.Name)
	resolved.Span = ref.Span
	return resolved
}

func sectionFromAttrs(attrs []ast.Attr) Section {
	for _, attr := range attrs {
		switch attr.Name {
		case "tracepoint":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramTracepoint,
				Attach: attach,
				Name:   "tracepoint/" + strings.ReplaceAll(attach, ":", "/"),
			}
		case "xdp":
			return Section{
				Kind: ProgramXDP,
				Name: "xdp",
			}
		case "tc":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramTC,
				Attach: attach,
				Name:   "tc/" + attach,
			}
		case "cgroup":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramCgroup,
				Attach: attach,
				Name:   "cgroup/" + attach,
			}
		case "lsm":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramLSM,
				Attach: attach,
				Name:   "lsm/" + attach,
			}
		case "kprobe":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramKprobe,
				Attach: attach,
				Name:   "kprobe/" + attach,
			}
		case "kretprobe":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramKretprobe,
				Attach: attach,
				Name:   "kretprobe/" + attach,
			}
		case "uprobe":
			// SEC("uprobe") is used rather than SEC("uprobe/binary:symbol") because
			// libbpf's embedded-path form requires double-slash and clang does not
			// validate attach targets at compile time. The binary and symbol are
			// loader-time concerns expressed via link.OpenExecutable(...).Uprobe(...).
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramUprobe,
				Attach: attach,
				Name:   "uprobe",
			}
		case "uretprobe":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramUretprobe,
				Attach: attach,
				Name:   "uretprobe",
			}
		case "fentry":
			// SEC("fentry") is used rather than SEC("fentry/symbol") because the
			// symbol is recorded in the BTF-based attach descriptor at load time via
			// link.AttachTracing(TracingOptions{Program: prog, AttachType: AttachTraceFEntry}).
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramFentry,
				Attach: attach,
				Name:   "fentry",
			}
		case "fexit":
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramFexit,
				Attach: attach,
				Name:   "fexit",
			}
		case "raw_tp":
			// SEC("raw_tp") is used rather than SEC("raw_tp/event") because the
			// event name is specified at load time via
			// link.AttachRawTracepoint(RawTracepointOptions{Name: event, Program: prog}).
			attach := stringArg(attr)
			return Section{
				Kind:   ProgramRawTP,
				Attach: attach,
				Name:   "raw_tp",
			}
		case "sockops":
			// SEC("sockops") uses a bare section name; the cgroup is attached at
			// load time via link.AttachCgroup(CgroupOptions{..., Attach: ebpf.AttachCGroupSockOps}).
			return Section{
				Kind:   ProgramSockOps,
				Attach: "",
				Name:   "sockops",
			}
		case "struct_ops":
			// SEC("struct_ops") is used with a bare section name; the op name is
			// recorded in Attach for manifest / namespace routing. struct_ops programs
			// replace kernel function pointers (e.g., TCP congestion control ops) and
			// require BTF + struct_ops map support (kernel >= 5.6).
			op := stringArg(attr)
			return Section{
				Kind:   ProgramStructOps,
				Attach: op,
				Name:   "struct_ops",
			}
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

// capabilityArgWithAxes resolves a @capability(name) attribute to its full identity:
// name, danger level, and danger axes.
// For string literals the axes are left as zero (caller derives them from the
// resolved danger level). For alias references the pre-computed axes are forwarded.
// Qualified `<alias>.<Name>` SelectorExpr references (roadmap #20 — Phase 2
// Subtask 3c) are looked up under their qualified key; the aliases map is
// expected to be populated with both bare local entries and qualified
// imported entries when the IR is built from a multi-package program.
func capabilityArgWithAxes(attr ast.Attr, aliases map[string]capabilityAlias) (string, DangerLevel, DangerAxes) {
	if len(attr.Args) == 0 {
		return "", "", DangerAxes{}
	}
	switch value := attr.Args[0].(type) {
	case ast.StringExpr:
		return value.Value, "", DangerAxes{}
	case ast.IdentExpr:
		alias := aliases[value.Name]
		return alias.Name, alias.Danger, alias.Axes
	case ast.SelectorExpr:
		operand, ok := value.Operand.(ast.IdentExpr)
		if !ok || operand.Name == "" || value.Field == "" {
			return "", "", DangerAxes{}
		}
		qualified := operand.Name + "." + value.Field
		alias := aliases[qualified]
		return alias.Name, alias.Danger, alias.Axes
	default:
		return "", "", DangerAxes{}
	}
}

type capabilityAccess struct {
	Maps  CapabilityMapAccess
	Emits string
}

func mapAccesses(fn Function, maps []Map) capabilityAccess {
	byName := map[string]Map{}
	for _, m := range maps {
		byName[m.Name] = m
	}
	seenRead := map[string]bool{}
	seenWrite := map[string]bool{}
	seenEvents := map[string]bool{}
	lookupVars := map[string]string{}
	access := capabilityAccess{
		Maps: CapabilityMapAccess{
			Read:   []string{},
			Write:  []string{},
			Events: []string{},
		},
	}
	var visitExpr func(*Expr)
	visitExpr = func(expr *Expr) {
		if expr == nil {
			return
		}
		if expr.Kind == "call" {
			mapName, method, ok := mapMethodCall(expr)
			if ok {
				m, known := byName[mapName]
				if known {
					switch method {
					case "lookup":
						addUnique(&access.Maps.Read, seenRead, mapName)
					case "update", "delete":
						addUnique(&access.Maps.Write, seenWrite, mapName)
					case "submit":
						if m.Kind == MapKindRingbuf {
							addUnique(&access.Maps.Events, seenEvents, mapName)
							if access.Emits == "" {
								access.Emits = m.Val.Name
							}
						}
					}
				}
			}
		}
		visitExpr(expr.Operand)
		visitExpr(expr.Left)
		visitExpr(expr.Right)
		visitExpr(expr.Func)
		for i := range expr.Args {
			visitExpr(&expr.Args[i])
		}
		for i := range expr.Fields {
			visitExpr(&expr.Fields[i].Value)
		}
	}
	var walk func([]Statement)
	walk = func(stmts []Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "short_var", "var_decl":
				visitExpr(stmt.Value)
				if mapName, method, ok := mapMethodCall(stmt.Value); ok && method == "lookup" {
					if _, known := byName[mapName]; known {
						lookupVars[stmt.Name] = mapName
					}
				}
			case "assign":
				if varName, ok := selectorBase(stmt.Target); ok {
					if mapName, ok := lookupVars[varName]; ok {
						addUnique(&access.Maps.Write, seenWrite, mapName)
					}
				}
				visitExpr(stmt.Target)
				visitExpr(stmt.Value)
			case "expr":
				visitExpr(stmt.Expr)
			case "return":
				visitExpr(stmt.Value)
			case "if":
				if stmt.Init != nil {
					walk([]Statement{*stmt.Init})
				}
				visitExpr(stmt.Cond)
				walk(stmt.Then)
				walk(stmt.Else)
			case "switch":
				visitExpr(stmt.Value)
				for _, c := range stmt.Cases {
					for i := range c.Values {
						visitExpr(&c.Values[i])
					}
					walk(c.Body)
				}
			case "for":
				if stmt.Init != nil {
					walk([]Statement{*stmt.Init})
				}
				visitExpr(stmt.Cond)
				if stmt.Post != nil {
					walk([]Statement{*stmt.Post})
				}
				walk(stmt.Body)
			}
		}
	}
	walk(functionStatements(fn))
	return access
}

func mapMethodCall(expr *Expr) (string, string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" {
		return "", "", false
	}
	switch expr.Func.Field {
	case "lookup", "update", "delete", "submit":
		return expr.Func.Operand.Name, expr.Func.Field, true
	default:
		return "", "", false
	}
}

func selectorBase(expr *Expr) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Kind {
	case "ident":
		return expr.Name, true
	case "selector":
		return selectorBase(expr.Operand)
	default:
		return "", false
	}
}

func addUnique(values *[]string, seen map[string]bool, value string) {
	if seen[value] {
		return
	}
	seen[value] = true
	*values = append(*values, value)
}

func inferDanger(fn Function) DangerLevel {
	if fn.Section.Kind != ProgramXDP && fn.Section.Kind != ProgramTC && fn.Section.Kind != ProgramCgroup && fn.Section.Kind != ProgramLSM {
		return DangerObserve
	}
	danger := DangerObserve
	var visit func([]Statement)
	visit = func(stmts []Statement) {
		for _, stmt := range stmts {
			switch stmt.Kind {
			case "return":
				switch qualifiedName(stmt.Value) {
				case "xdp.Drop", "xdp.Aborted":
					danger = moreDangerous(danger, DangerDrop)
				case "xdp.Tx", "xdp.Redirect":
					danger = moreDangerous(danger, DangerMutate)
				case "tc.Shot", "tc.Stolen":
					danger = moreDangerous(danger, DangerDrop)
				case "tc.Reclassify", "tc.Redirect":
					danger = moreDangerous(danger, DangerMutate)
				case "cgroup.Deny":
					danger = moreDangerous(danger, DangerBlock)
				case "lsm.Deny":
					danger = moreDangerous(danger, DangerBlock)
				}
			case "if":
				if stmt.Init != nil {
					visit([]Statement{*stmt.Init})
				}
				visit(stmt.Then)
				visit(stmt.Else)
			case "switch":
				for _, c := range stmt.Cases {
					visit(c.Body)
				}
			case "for":
				visit(stmt.Body)
			}
		}
	}
	visit(functionStatements(fn))
	return danger
}

func declaredDanger(declared DangerLevel, inferred DangerLevel) DangerLevel {
	if declared == "" {
		return inferred
	}
	return moreDangerous(declared, inferred)
}

func capabilityNameDanger(name string) DangerLevel {
	_, suffix, ok := strings.Cut(strings.TrimSpace(name), ".")
	for ok {
		name = suffix
		_, suffix, ok = strings.Cut(name, ".")
	}
	switch DangerLevel(name) {
	case DangerObserve, DangerMutate, DangerDrop, DangerBlock, DangerPrivileged:
		return DangerLevel(name)
	default:
		return ""
	}
}

func moreDangerous(current DangerLevel, next DangerLevel) DangerLevel {
	rank := map[DangerLevel]int{
		DangerObserve:    0,
		DangerMutate:     1,
		DangerDrop:       2,
		DangerBlock:      3,
		DangerPrivileged: 4,
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}

func qualifiedName(expr *Expr) string {
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "selector":
		prefix := qualifiedName(expr.Operand)
		if prefix == "" {
			return expr.Field
		}
		return prefix + "." + expr.Field
	default:
		return ""
	}
}

func functionStatements(fn Function) []Statement {
	var out []Statement
	for _, block := range fn.Body {
		out = append(out, block.Statements...)
	}
	return out
}

