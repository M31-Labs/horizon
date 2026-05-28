package types

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
)

// isExported mirrors Go's convention: a top-level declaration is exported
// iff its first rune is upper-case. Empty names are not exported. This is
// the central predicate behind the v0.3 cross-package privacy gate
// (roadmap #17): every qualified `<alias>.<name>` lookup from another
// package is rejected with one of HZN1670–HZN1674 when the named symbol
// is not exported. Privacy is enforced cross-package only — same-package
// references to lowercase symbols remain legal.
func isExported(name string) bool {
	if name == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r)
}

// suggestExportedRename returns the input name with its first rune
// upper-cased, suitable for inclusion in a `Suggest` field on an
// HZN1670–HZN1674 diagnostic. Names whose first rune is already
// upper-case (or whose first rune has no upper-case mapping) are
// returned unchanged.
func suggestExportedRename(name string) string {
	if name == "" {
		return name
	}
	r, size := utf8.DecodeRuneInString(name)
	upper := unicode.ToUpper(r)
	if upper == r {
		return name
	}
	return string(upper) + name[size:]
}

// importedDeclKind tags a top-level declaration in an imported package so
// the privacy walk can choose the right diagnostic code per kind
// (HZN1671 funcs, HZN1672 maps, HZN1674 consts). Types and capabilities
// are gated separately in validateQualifiedSelectorRefs and
// validateCapabilityAttr respectively, so they do not appear here.
type importedDeclKind int

const (
	importedDeclUnknown importedDeclKind = iota
	importedDeclFunc
	importedDeclMap
	importedDeclConst
)

// importedPrivacyIndex maps `alias` → `name` → kind for every top-level
// non-type, non-capability declaration in each imported package. Used by
// validateQualifiedPrivacyRefs to surface a privacy diagnostic when an
// importer references a present-but-unexported symbol via qualified
// selector. Names that are not present in the imported package fall
// through to whatever existing diagnostic (HZN1414 / HZN1404) covered the
// case before v0.3.
type importedPrivacyIndex map[string]map[string]importedDeclKind

func buildImportedPrivacyIndex(importedPkgs map[string]ast.Package) importedPrivacyIndex {
	if len(importedPkgs) == 0 {
		return nil
	}
	out := importedPrivacyIndex{}
	for alias, pkg := range importedPkgs {
		kinds := map[string]importedDeclKind{}
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case ast.FuncDecl:
					if d.Name != "" {
						kinds[d.Name] = importedDeclFunc
					}
				case ast.MapDecl:
					if d.Name != "" {
						kinds[d.Name] = importedDeclMap
					}
				case ast.ConstDecl:
					if d.Name != "" {
						kinds[d.Name] = importedDeclConst
					}
				case ast.ConstGroupDecl:
					for _, c := range d.Consts {
						if c.Name != "" {
							kinds[c.Name] = importedDeclConst
						}
					}
				case ast.EnumDecl:
					for _, v := range d.Values {
						if v.Name != "" {
							kinds[v.Name] = importedDeclConst
						}
					}
				}
			}
		}
		if len(kinds) > 0 {
			out[alias] = kinds
		}
	}
	return out
}

// validateQualifiedPrivacyRefs walks every expression in a file and emits
// HZN1671 (qualified func call), HZN1672 (qualified map ref), or HZN1674
// (qualified const ref) when an importer references a lowercase symbol in
// another package via `<alias>.<name>`. Qualified type references and
// qualified capability attribute references are gated upstream
// (validateQualifiedSelectorRefs / validateCapabilityAttr), so this walk
// only covers the call/value-selector positions reached by the function-
// body type-checker.
//
// The walk is conservative — when the alias is unknown to the privacy
// index (e.g. a builtin namespace such as `bpf`) or the symbol is not
// declared in the imported package, no privacy diagnostic fires and the
// existing fallback diagnostics (HZN1414, HZN1404, HZN1557, etc.) handle
// the case as before. The walk also skips compiler namespaces that
// don't appear in the importAliases set.
func validateQualifiedPrivacyRefs(file ast.File, importAliases map[string]bool, privacyIndex importedPrivacyIndex) []diag.Diagnostic {
	if len(importAliases) == 0 || len(privacyIndex) == 0 {
		return nil
	}
	var diags []diag.Diagnostic
	emit := func(code, kindLabel, alias, name string, sp ast.Expr) {
		diags = append(diags, diag.Diagnostic{
			Code:     code,
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("%s %q is not exported from package %q", kindLabel, name, alias),
			Primary:  sp.GetSpan(),
			Suggest:  fmt.Sprintf("capitalize %q to export it from package %q (e.g. rename to %s and update call sites)", name, alias, suggestExportedRename(name)),
		})
	}
	var walkExpr func(expr ast.Expr)
	walkExpr = func(expr ast.Expr) {
		if expr == nil {
			return
		}
		switch e := expr.(type) {
		case ast.CallExpr:
			// Qualified call form `<alias>.<name>(...)`. Inspect the
			// callee selector before recursing into the operand — the
			// privacy diagnostic for the callee takes precedence over
			// any privacy diagnostic on the receiver's operand chain.
			if sel, ok := e.Func.(ast.SelectorExpr); ok {
				if alias, name, qok := selectorAliasAndField(sel); qok && importAliases[alias] && !isExported(name) {
					if kinds, ok := privacyIndex[alias]; ok {
						if kind, present := kinds[name]; present && kind == importedDeclFunc {
							emit("HZN1671", "function", alias, name, sel)
							// fall through to walk args; do not double-emit on sel
							for _, arg := range e.Args {
								walkExpr(arg)
							}
							return
						}
					}
				}
			}
			walkExpr(e.Func)
			for _, arg := range e.Args {
				walkExpr(arg)
			}
		case ast.SelectorExpr:
			if alias, name, qok := selectorAliasAndField(e); qok && importAliases[alias] && !isExported(name) {
				if kinds, ok := privacyIndex[alias]; ok {
					if kind, present := kinds[name]; present {
						switch kind {
						case importedDeclMap:
							emit("HZN1672", "map", alias, name, e)
							return
						case importedDeclConst:
							emit("HZN1674", "constant", alias, name, e)
							return
						case importedDeclFunc:
							// A bare selector to a func (not in call
							// position) — Horizon has no function-value
							// surface today, but emit HZN1671 for
							// consistency so the diagnostic still names
							// the right kind.
							emit("HZN1671", "function", alias, name, e)
							return
						}
					}
				}
			}
			walkExpr(e.Operand)
		case ast.UnaryExpr:
			walkExpr(e.Expr)
		case ast.BinaryExpr:
			walkExpr(e.Left)
			walkExpr(e.Right)
		case ast.StructLiteralExpr:
			for _, f := range e.Fields {
				walkExpr(f.Value)
			}
		}
	}
	var walkStmts func(stmts []ast.Stmt)
	walkStmt := func(stmt ast.Stmt) {
		// Defined below; placeholder body to allow walkStmts to reference it.
		_ = stmt
	}
	walkStmts = func(stmts []ast.Stmt) {
		for _, s := range stmts {
			walkStmt(s)
		}
	}
	walkStmt = func(stmt ast.Stmt) {
		if stmt == nil {
			return
		}
		switch s := stmt.(type) {
		case ast.ShortVarStmt:
			walkExpr(s.Value)
		case ast.VarDeclStmt:
			walkExpr(s.Value)
		case ast.AssignStmt:
			walkExpr(s.Target)
			walkExpr(s.Value)
		case ast.ReturnStmt:
			walkExpr(s.Value)
		case ast.IfStmt:
			walkStmt(s.Init)
			walkExpr(s.Cond)
			walkStmts(s.Then)
			walkStmts(s.Else)
		case ast.ForStmt:
			walkStmt(s.Init)
			walkExpr(s.Cond)
			walkStmt(s.Post)
			walkStmts(s.Body)
		case ast.SwitchStmt:
			walkExpr(s.Value)
			for _, c := range s.Cases {
				for _, v := range c.Values {
					walkExpr(v)
				}
				walkStmts(c.Body)
			}
		case ast.ExprStmt:
			walkExpr(s.Expr)
		}
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(ast.FuncDecl); ok {
			walkStmts(fn.Body)
		}
	}
	return diags
}
