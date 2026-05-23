package emitc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
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
		"static __always_inline struct ExecEvent *ExecEvents_reserve(void)",
		"struct ExecEvent *event = ExecEvents_reserve();",
		"event->pid = hzn_current_pid();",
		"hzn_current_comm(&event->comm, sizeof(event->comm));",
		"ExecEvents_submit(event);",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
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

func TestEmitHashMapMethods(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    Counts.update(pid, pid)
    value := Counts.lookup(pid)
    if value == nil {
        return 0
    }
    Counts.delete(pid)
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
		"Counts_update(pid, pid);",
		"__u32 *value = Counts_lookup(pid);",
		"Counts_delete(pid);",
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
    Counts.update(pid, state)
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
		"static __always_inline long Counts_update(__u32 key, struct Count value)",
		"struct Count state = (struct Count){ .seen = pid };",
		"state.seen = hzn_current_pid();",
		"__u32 seen = state.seen;",
		"Counts_update(pid, state);",
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
func DropAll(ctx xdp.Context) i32 {
    return xdp.Drop
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
		"#define XDP_DROP 1",
		"SEC(\"xdp\")",
		"int DropAll(struct xdp_md *ctx) {",
		"return XDP_DROP;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}
