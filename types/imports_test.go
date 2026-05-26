package types

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
)

// TestCompilerNamespaceWithUserAliases pins the alias-aware namespace check.
// Without aliases, the hardcoded compiler namespaces (bpf/xdp/...) are
// reserved. When an explicit user-package alias set is threaded through, an
// alias such as "events" is reported as a namespace (so it cannot be
// shadowed by a sibling top-level decl), but it must NOT collide with the
// HZN1004 compiler-namespace path because users declare their own aliases.
func TestCompilerNamespaceWithUserAliases(t *testing.T) {
	if !compilerNamespace("bpf") {
		t.Fatalf("compilerNamespace(\"bpf\") = false, want true (hardcoded namespace)")
	}
	if compilerNamespace("events") {
		t.Fatalf("compilerNamespace(\"events\") = true, want false (no aliases threaded)")
	}
	if !compilerNamespaceWithAliases("bpf", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"bpf\", {events}) = false, want true")
	}
	if !compilerNamespaceWithAliases("events", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"events\", {events}) = true requires alias awareness")
	}
	if compilerNamespaceWithAliases("other", map[string]bool{"events": true}) {
		t.Fatalf("compilerNamespaceWithAliases(\"other\", {events}) = true, want false")
	}
}

// TestDeclareNameAllowsUserPackageAlias verifies the additive integration:
// declarePackageName, when threaded an alias set, treats user-package aliases
// as a reserved namespace WITHOUT firing the HZN1004 compiler-namespace
// collision diagnostic. The collision case for user aliases is reserved for
// a separate diagnostic in subsequent subtasks; this test only pins that
// HZN1004 does not fire for them.
func TestDeclareNameAllowsUserPackageAlias(t *testing.T) {
	env := NewEnv()
	var diags []diag.Diagnostic
	decl := stubDeclRef{span: span.Span{File: "a.hzn"}}
	ok := declarePackageNameWithAliases(&diags, env, "events", decl, map[string]bool{"events": true})
	if ok {
		t.Fatalf("declarePackageNameWithAliases returned true; want false because the alias \"events\" reserves the name")
	}
	if idx := slices.IndexFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1004" }); idx >= 0 {
		t.Fatalf("user-package alias must NOT trigger HZN1004; got %#v", diags[idx])
	}
}

type stubDeclRef struct {
	span span.Span
}

func (s stubDeclRef) GetSpan() span.Span { return s.span }

// satisfy ast.Decl is not required — DeclRef only requires GetSpan.
var _ DeclRef = stubDeclRef{}
var _ = ast.File{}
