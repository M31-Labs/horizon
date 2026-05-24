package emitc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/ir"
)

func TestEmitExecwatchUsesTypedCWrappers(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		`_Static_assert(sizeof(__u32) == 4, "horizon: __u32 width mismatch");`,
		"static __always_inline struct ExecEvent *ExecEvents_reserve(void)",
		"static __always_inline void ExecEvents_submit(struct ExecEvent *value)",
		`_Static_assert(sizeof(struct ExecEvent) == 28, "horizon: struct ExecEvent size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct ExecEvent, comm) == 12, "horizon: struct ExecEvent.comm offset mismatch");`,
		"(void)ctx;",
		"struct ExecEvent *event = ExecEvents_reserve();",
		"event->pid = hzn_current_pid();",
		"hzn_current_comm(&event->comm, sizeof(event->comm));",
		"ExecEvents_submit(event);",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	for _, unwanted := range []string{
		"ExecEvents_discard",
		"__attribute__((unused))",
	} {
		if strings.Contains(out.Code, unwanted) {
			t.Fatalf("generated C contains unused wrapper %q:\n%s", unwanted, out.Code)
		}
	}
}

func TestEmitBoundedForClause(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loop.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    for i := 0; i < 4; i++ {
        bpf.current_pid()
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.Contains(out.Code, "for (__s64 i = 0; i < 4; i++) {") {
		t.Fatalf("generated C missing bounded for clause:\n%s", out.Code)
	}
}

func TestEmitIfElse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "branch.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if pid == 0 {
        return 0
    } else {
        return 1
    }
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"if (pid == 0) {",
		"} else {",
		"return 1;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	for _, unwanted := range []string{
		"hzn_current_ppid",
		"hzn_current_uid",
		"hzn_current_comm",
	} {
		if strings.Contains(out.Code, unwanted) {
			t.Fatalf("generated C contains unused kernel helper wrapper %q:\n%s", unwanted, out.Code)
		}
	}
}

func TestEmitHashMapMethods(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, pid) != 0 {
        return 0
    }
    value := Counts.lookup(pid)
    if value == nil {
        return 0
    }
    if Counts.delete(pid) != 0 {
        return 0
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"__uint(type, BPF_MAP_TYPE_HASH);",
		"__type(key, __u32);",
		"__type(value, __u32);",
		"static __always_inline __u32 *Counts_lookup(__u32 key)",
		"static __always_inline long Counts_update(__u32 key, __u32 value)",
		"static __always_inline long Counts_delete(__u32 key)",
		"if (Counts_update(pid, pid) != 0) {",
		"__u32 *value = Counts_lookup(pid);",
		"if (Counts_delete(pid) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitStructLiteralMapUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    state := Count{seen: pid}
    state.seen = bpf.current_pid()
    seen := state.seen
    if Counts.update(pid, state) != 0 {
        return 0
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"struct Count {",
		`_Static_assert(sizeof(struct Count) == 4, "horizon: struct Count size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct Count, seen) == 0, "horizon: struct Count.seen offset mismatch");`,
		"static __always_inline long Counts_update(__u32 key, struct Count value)",
		"struct Count state = (struct Count){ .seen = pid };",
		"state.seen = hzn_current_pid();",
		"__u32 seen = state.seen;",
		"if (Counts_update(pid, state) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	for _, unwanted := range []string{
		"Counts_lookup",
		"Counts_delete",
	} {
		if strings.Contains(out.Code, unwanted) {
			t.Fatalf("generated C contains unused map wrapper %q:\n%s", unwanted, out.Code)
		}
	}
}

func TestEmitStructLayoutAssertionsIncludePadding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "layout.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type LayoutEvent struct {
    tag u8
    pid u32
    ports [3]u16
}

map Events ringbuf[LayoutEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    event.tag = 1
    event.pid = bpf.current_pid()
    Events.submit(event)
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		`_Static_assert(sizeof(struct LayoutEvent) == 16, "horizon: struct LayoutEvent size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct LayoutEvent, tag) == 0, "horizon: struct LayoutEvent.tag offset mismatch");`,
		`_Static_assert(__builtin_offsetof(struct LayoutEvent, pid) == 4, "horizon: struct LayoutEvent.pid offset mismatch");`,
		`_Static_assert(__builtin_offsetof(struct LayoutEvent, ports) == 8, "horizon: struct LayoutEvent.ports offset mismatch");`,
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitIntegerConst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const FirstSeen = 1

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, FirstSeen) != 0 {
        return 0
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static const __u64 FirstSeen = 1;",
		"if (Counts_update(pid, FirstSeen) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitTypedIntegerAndBooleanOperators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const Mask = 0x0f

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    bucket := (pid & Mask) + 1
    if bucket != 0 && pid > 0 {
        if Counts.update(bucket, pid) != 0 {
            return 0
        }
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static const __u64 Mask = 0x0f;",
		"__u32 bucket = (pid & Mask) + 1;",
		"if ((bucket != 0) && (pid > 0)) {",
		"if (Counts_update(bucket, pid) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitMapLookupUsesPointerSelector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    if count == nil {
        return 0
    }
    seen := count.seen
    count.seen = pid
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"struct Count *count = Counts_lookup(pid);",
		"__u32 seen = count->seen;",
		"count->seen = pid;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitXDPProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xdp.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    if xdp.ntohs(tcp.dst_port) == 443 {
        return xdp.Drop
    }
    return xdp.Pass
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"#include <bpf/bpf_endian.h>",
		"#define XDP_DROP 1",
		"struct hzn_xdp_ipv4 {",
		"struct hzn_xdp_tcp {",
		"struct hzn_xdp_udp {",
		"static __always_inline struct hzn_xdp_ipv4 *hzn_xdp_ipv4(struct xdp_md *ctx)",
		"static __always_inline __u64 hzn_xdp_l4_offset(struct xdp_md *ctx, __u8 protocol)",
		"static __always_inline struct hzn_xdp_tcp *hzn_xdp_tcp(struct xdp_md *ctx)",
		"__u8 ihl = ip->version_ihl & 0x0f;",
		"SEC(\"xdp\")",
		"int DropTCP(struct xdp_md *ctx) {",
		"struct hzn_xdp_tcp *tcp = hzn_xdp_tcp(ctx);",
		"if (tcp == 0) {",
		"return XDP_PASS;",
		"if (bpf_ntohs(tcp->dst_port) == 443) {",
		"return XDP_DROP;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	if strings.Contains(out.Code, "static __always_inline struct hzn_xdp_udp *hzn_xdp_udp") {
		t.Fatalf("generated C contains unused UDP packet helper:\n%s", out.Code)
	}
}

func TestEmitKprobeProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.hzn")
	if err := os.WriteFile(path, []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    bpf.current_pid()
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		`SEC("kprobe/do_sys_openat2")`,
		"int OnOpen(struct pt_regs *ctx) {",
		"hzn_current_pid();",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitRejectsUnsupportedStatementKind(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{{Kind: "while"}},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for unsupported statement:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported statement kind "while"`) {
		t.Fatalf("Emit error = %v, want unsupported statement kind", err)
	}
}

func TestEmitRejectsUnsupportedExpressionKind(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "expr",
					Expr: &ir.Expr{Kind: "string", Value: "not C"},
				}},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for unsupported expression:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported expression kind "string"`) {
		t.Fatalf("Emit error = %v, want unsupported expression kind", err)
	}
}

func TestEmitRejectsUnknownCallTarget(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "expr",
					Expr: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{
							Kind:    "selector",
							Operand: &ir.Expr{Kind: "ident", Name: "bpf"},
							Field:   "raw_helper",
						},
					},
				}},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for unknown call target:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported expression kind "bpf.raw_helper"`) {
		t.Fatalf("Emit error = %v, want unsupported call target", err)
	}
}

func TestEmitRejectsIdentifierOutsideBranchScope(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{
					{
						Kind: "if",
						Cond: &ir.Expr{
							Kind:  "binary",
							Op:    "!=",
							Left:  helperCall("current_pid"),
							Right: &ir.Expr{Kind: "int", Value: "0"},
						},
						Then: []ir.Statement{{
							Kind:  "short_var",
							Name:  "branch",
							Value: helperCall("current_pid"),
						}},
					},
					{Kind: "expr", Expr: &ir.Expr{Kind: "ident", Name: "branch"}},
				},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for out-of-scope branch local:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported expression kind "unknown identifier branch"`) {
		t.Fatalf("Emit error = %v, want unknown branch identifier", err)
	}
}

func TestEmitRejectsIdentifierOutsideForScope(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{
					{
						Kind: "for",
						Init: &ir.Statement{Kind: "short_var", Name: "i", Value: &ir.Expr{Kind: "int", Value: "0"}},
						Cond: &ir.Expr{
							Kind:  "binary",
							Op:    "<",
							Left:  &ir.Expr{Kind: "ident", Name: "i"},
							Right: &ir.Expr{Kind: "int", Value: "4"},
						},
						Post: &ir.Statement{Kind: "inc", Name: "i", Op: "++"},
					},
					{Kind: "expr", Expr: &ir.Expr{Kind: "ident", Name: "i"}},
				},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for out-of-scope for local:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported expression kind "unknown identifier i"`) {
		t.Fatalf("Emit error = %v, want unknown for identifier", err)
	}
}

func helperCall(name string) *ir.Expr {
	return &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "bpf"},
			Field:   name,
		},
	}
}
