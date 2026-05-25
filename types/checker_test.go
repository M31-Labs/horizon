package types

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/ast"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/parser"
)

func TestCheckFunctionParametersAreInScope(t *testing.T) {
	file := ast.File{
		Package: "probes",
		Decls: []ast.Decl{
			ast.FuncDecl{
				Name: "OnExec",
				Attrs: []ast.Attr{{
					Name: "tracepoint",
					Args: []ast.Expr{ast.StringExpr{Value: "sched:sched_process_exec"}},
				}},
				Params: []ast.Param{{
					Name: "ctx",
					Type: ast.TypeRef{Name: "tracepoint.Exec"},
				}},
				Return: ast.TypeRef{Name: "i32"},
				Body: []ast.Stmt{
					ast.ShortVarStmt{Name: "seen", Value: ast.IdentExpr{Name: "ctx"}},
					ast.ReturnStmt{Value: ast.IntExpr{Value: "0"}},
				},
			},
		},
	}
	diags := Check(file)
	if slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1404" }) {
		t.Fatalf("diagnostics = %#v, want function parameter in scope", diags)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want no errors", diags)
	}
}

func TestCheckCgroupConnectHelpers(t *testing.T) {
	file := parseTestFile(t, `package probes

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.family(ctx) != cgroup.FamilyIPv4 {
        return cgroup.Allow
    }
    if cgroup.sock_type(ctx) != cgroup.SockStream {
        return cgroup.Allow
    }
    if cgroup.protocol(ctx) != cgroup.ProtocolTCP {
        return cgroup.Allow
    }
    if (cgroup.dst_port(ctx) == 25) && (cgroup.dst_ip4(ctx) != cgroup.ip4(127, 0, 0, 1)) {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`)
	diags := Check(file)
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want no errors", diags)
	}
}

func TestCheckRejectsInvalidCgroupIP4Octet(t *testing.T) {
	file := parseTestFile(t, `package probes

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.dst_ip4(ctx) == cgroup.ip4(127, 0, 0, 300) {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`)
	diags := Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1469" }) {
		t.Fatalf("diagnostics = %#v, want HZN1469", diags)
	}
}

func TestCheckRejectsInvalidCgroupIP4ConstOctet(t *testing.T) {
	file := parseTestFile(t, `package probes

const LoopbackOctet = 300

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.dst_ip4(ctx) == cgroup.ip4(127, 0, 0, LoopbackOctet) {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`)
	diags := Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1469" }) {
		t.Fatalf("diagnostics = %#v, want HZN1469", diags)
	}
}

func TestCapabilityUnknownLeaf(t *testing.T) {
	file := parseTestFile(t, `package probes

capability ConnectGrant danger block = "kernel.network.connect.grant"

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    return cgroup.Allow
}
`)
	diags := Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1326" }) {
		t.Fatalf("diagnostics = %#v, want HZN1326", diags)
	}
}

func TestCapabilityRecognizedLeafAllowed(t *testing.T) {
	file := parseTestFile(t, `package probes

capability ConnectBlock danger block = "kernel.network.connect.block"

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    return cgroup.Allow
}
`)
	diags := Check(file)
	if slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1326" }) {
		t.Fatalf("diagnostics = %#v, want no HZN1326", diags)
	}
}

func parseTestFile(t *testing.T, source string) ast.File {
	t.Helper()
	parsed, err := parser.ParseSource(parser.SourceFile{Path: "inline.hzn", Bytes: []byte(source)})
	if err != nil {
		t.Fatalf("ParseSource: %v", err)
	}
	file, err := ast.Build(parsed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return *file
}
