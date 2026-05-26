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

func TestHelperFunctionAcceptsResourceParam(t *testing.T) {
	file := parseTestFile(t, `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

func record(event *Event) bool {
    Events.submit(event)
    return true
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    record(event)
    return 0
}
`)
	diags := Check(file)
	if slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1319" }) {
		t.Fatalf("diagnostics = %#v, want no HZN1319 on resource-typed helper param", diags)
	}
}

func TestHelperResourceReturnStillRejected(t *testing.T) {
	file := parseTestFile(t, `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

func badReturn(ev *Event) *Event {
    return ev
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    badReturn(event)
    return 0
}
`)
	diags := Check(file)
	if !slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1320" }) {
		t.Fatalf("diagnostics = %#v, want HZN1320 on resource-typed helper return", diags)
	}
}

// TestHelperCallArgDoesNotTriggerAliasDiagnostic regression-pins the audit at
// types/checker.go (HZN1447 emission points 1997, 2076, 2164): none of them sit
// on the user-helper call-argument path (userFunctionCall at line 3585 uses
// HZN1502 for arg-type mismatches, not HZN1447). Passing a tracked pointer as a
// helper call argument therefore must not fire HZN1447. This pins that the
// HZN1319 relaxation in commit 2.8a did not inadvertently route alias-copy
// rejection onto the helper-arg path.
func TestHelperCallArgDoesNotTriggerAliasDiagnostic(t *testing.T) {
	file := parseTestFile(t, `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

func record(event *Event) bool {
    Events.submit(event)
    return true
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    record(event)
    return 0
}
`)
	diags := Check(file)
	if slices.ContainsFunc(diags, func(d diag.Diagnostic) bool { return d.Code == "HZN1447" }) {
		t.Fatalf("diagnostics = %#v, want no HZN1447 on helper-call argument", diags)
	}
}

// TestStatementLevelAliasStillEmitsHZN1447 regression-pins that the HZN1319
// relaxation in commit 2.8a did NOT silence the statement-level alias guard.
// The `alias := event` rebind after a tracked-pointer reserve must still fire
// HZN1447 (the emission point at types/checker.go:1997 — ShortVarStmt).
func TestStatementLevelAliasStillEmitsHZN1447(t *testing.T) {
	file := parseTestFile(t, `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    alias := event
    Events.submit(alias)
    return 0
}
`)
	diags := Check(file)
	var hits int
	for _, d := range diags {
		if d.Code == "HZN1447" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("diagnostics = %#v, want exactly one HZN1447 on statement-level alias, got %d", diags, hits)
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
