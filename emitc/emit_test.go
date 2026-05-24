package emitc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
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
		"#include <bpf/bpf_core_read.h>",
		`_Static_assert(sizeof(__u32) == 4, "horizon: __u32 width mismatch");`,
		"struct task_struct *task = (struct task_struct *)bpf_get_current_task();",
		"bpf_core_read(&parent, sizeof(parent), &task->real_parent)",
		"bpf_core_read(&ppid, sizeof(ppid), &parent->tgid)",
		"return ppid;",
		"static __always_inline struct hzn_type_ExecEvent *ExecEvents_reserve(void)",
		"static __always_inline void ExecEvents_submit(struct hzn_type_ExecEvent *value)",
		"static __always_inline __u64 hzn_ktime_get_ns(void)",
		`_Static_assert(sizeof(struct hzn_type_ExecEvent) == 40, "horizon: struct ExecEvent size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, ts_ns) == 0, "horizon: struct ExecEvent.ts_ns offset mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, comm) == 20, "horizon: struct ExecEvent.comm offset mismatch");`,
		"(void)ctx;",
		"struct hzn_type_ExecEvent *event = ExecEvents_reserve();",
		"event->ts_ns = hzn_ktime_get_ns();",
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

func TestEmitOrdersNestedStructDependencies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Outer struct {
    inner Inner
    pid u32
}

type Inner struct {
    uid u32
}

map Events ringbuf[Outer]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	innerIndex := strings.Index(out.Code, "struct hzn_type_Inner {")
	outerIndex := strings.Index(out.Code, "struct hzn_type_Outer {")
	if innerIndex < 0 || outerIndex < 0 || innerIndex > outerIndex {
		t.Fatalf("generated C did not emit Inner before Outer:\n%s", out.Code)
	}
	if !strings.Contains(out.Code, "struct hzn_type_Inner inner;") {
		t.Fatalf("generated C missing nested struct field:\n%s", out.Code)
	}
}

func TestEmitSourceMapIncludesDeclarations(t *testing.T) {
	result, err := compiler.AnalyzePath("../testdata/golden/exec/input.hzn")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	assertSourceMapLine(t, out, "struct hzn_type_ExecEvent {", "struct", 5)
	assertSourceMapLine(t, out, `} ExecEvents SEC(".maps");`, "map", 13)
	assertSourceMapLine(t, out, "static __always_inline __u32 hzn_current_ppid(void)", "helper_wrapper", 24)
	assertSourceMapLine(t, out, "static __always_inline long hzn_current_comm(void *dst, __u32 size)", "helper_wrapper", 26)
	assertSourceMapLine(t, out, "static __always_inline struct hzn_type_ExecEvent *ExecEvents_reserve(void)", "map_wrapper", 18)
	assertSourceMapLine(t, out, "int OnExec(struct trace_event_raw_sched_process_exec *ctx)", "function", 15)

	result, err = compiler.AnalyzePath("../examples/execcount")
	if err != nil {
		t.Fatalf("AnalyzePath execcount: %v", err)
	}
	out, err = Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit execcount: %v", err)
	}
	assertSourceMapLine(t, out, "static const __u64 hzn_const_FirstSeen = 1;", "const", 5)
}

func TestEmitSourceMapIncludesGeneratedHelperWrappers(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath execwatch: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit execwatch: %v", err)
	}
	assertSourceMapLine(t, out, "static __always_inline struct hzn_type_ExecEvent *ExecEvents_reserve", "map_wrapper", 18)
	assertSourceMapLine(t, out, "static __always_inline void ExecEvents_submit", "map_wrapper", 27)

	result, err = compiler.AnalyzePath("../examples/openwatch")
	if err != nil {
		t.Fatalf("AnalyzePath openwatch: %v", err)
	}
	out, err = Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit openwatch: %v", err)
	}
	assertSourceMapLine(t, out, "static __always_inline long hzn_probe_read_user_str", "helper_wrapper", 24)
	assertSourceMapLine(t, out, "static __always_inline __u64 hzn_kprobe_arg2", "probe_context_wrapper", 24)

	result, err = compiler.AnalyzePath("../examples/xdpdrop")
	if err != nil {
		t.Fatalf("AnalyzePath xdpdrop: %v", err)
	}
	out, err = Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit xdpdrop: %v", err)
	}
	assertSourceMapLine(t, out, "static __always_inline __u64 hzn_xdp_l4_offset", "xdp_helper_wrapper", 6)
	assertSourceMapLine(t, out, "static __always_inline struct hzn_xdp_tcp *hzn_xdp_tcp", "xdp_helper_wrapper", 6)

	result, err = compiler.AnalyzePath("../examples/cgroupconnect")
	if err != nil {
		t.Fatalf("AnalyzePath cgroupconnect: %v", err)
	}
	out, err = Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit cgroupconnect: %v", err)
	}
	assertSourceMapLine(t, out, "static __always_inline __u32 hzn_cgroup_family", "cgroup_context_wrapper", 6)
	assertSourceMapLine(t, out, "static __always_inline __u16 hzn_cgroup_dst_port", "cgroup_context_wrapper", 12)

	result, err = compiler.AnalyzePath("../examples/execcount")
	if err != nil {
		t.Fatalf("AnalyzePath execcount: %v", err)
	}
	out, err = Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit execcount: %v", err)
	}
	assertSourceMapLine(t, out, "static __always_inline struct hzn_type_Count *ExecCounts_lookup", "map_wrapper", 17)
	assertSourceMapLine(t, out, "static __always_inline long ExecCounts_update", "map_wrapper", 19)
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

func TestEmitConstBoundedForClause(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loop.hzn")
	if err := os.WriteFile(path, []byte(`package probes

const MaxSamples u32 = 4

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    for i := 0; i < MaxSamples; i++ {
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, needle := range []string{
		"static const __u32 hzn_const_MaxSamples = 4;",
		"for (__u32 i = 0; i < hzn_const_MaxSamples; i++) {",
	} {
		if !strings.Contains(out.Code, needle) {
			t.Fatalf("generated C missing %q:\n%s", needle, out.Code)
		}
	}
}

func TestEmitIfInitLookupScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if count := Counts.lookup(pid); count != nil {
        count.seen = count.seen + 1
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, needle := range []string{
		"{\n        struct hzn_type_Count *count = Counts_lookup(pid);",
		"if (count != 0) {",
		"count->seen = count->seen + 1;",
	} {
		if !strings.Contains(out.Code, needle) {
			t.Fatalf("generated C missing %q:\n%s", needle, out.Code)
		}
	}
}

func TestEmitIfInitPacketScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xdp.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    if tcp := xdp.tcp(ctx); tcp != nil {
        if xdp.ntohs(tcp.dst_port) == 443 {
            return xdp.Drop
        }
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, needle := range []string{
		"{\n        struct hzn_xdp_tcp *tcp = hzn_xdp_tcp(ctx);",
		"if (tcp != 0) {",
		"if (bpf_ntohs(tcp->dst_port) == 443) {",
	} {
		if !strings.Contains(out.Code, needle) {
			t.Fatalf("generated C missing %q:\n%s", needle, out.Code)
		}
	}
}

func assertSourceMapLine(t *testing.T, out Output, generatedNeedle string, wantNode string, wantSourceLine int) {
	t.Helper()
	line := generatedLineContaining(t, out.Code, generatedNeedle)
	mapping, ok := sourceMapMappingForLine(out.SourceMap.Mappings, line)
	if !ok {
		t.Fatalf("source map missing generated line %d for %q; mappings = %#v", line, generatedNeedle, out.SourceMap.Mappings)
	}
	if mapping.Node != wantNode {
		t.Fatalf("mapping node for %q = %q, want %q; mapping = %#v", generatedNeedle, mapping.Node, wantNode, mapping)
	}
	if mapping.Source.Start.Line != wantSourceLine {
		t.Fatalf("mapping source line for %q = %d, want %d; mapping = %#v", generatedNeedle, mapping.Source.Start.Line, wantSourceLine, mapping)
	}
}

func generatedLineContaining(t *testing.T, code string, needle string) int {
	t.Helper()
	for i, line := range strings.Split(code, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("generated C missing %q:\n%s", needle, code)
	return 0
}

func sourceMapMappingForLine(mappings []ir.SourceMapping, line int) (ir.SourceMapping, bool) {
	var best ir.SourceMapping
	bestSet := false
	for _, mapping := range mappings {
		if mapping.Generated.Start.Line == 0 || line < mapping.Generated.Start.Line || line >= mapping.Generated.End.Line {
			continue
		}
		if !bestSet || mappingSize(mapping) < mappingSize(best) {
			best = mapping
			bestSet = true
		}
	}
	return best, bestSet
}

func mappingSize(mapping ir.SourceMapping) int {
	return mapping.Generated.End.Line - mapping.Generated.Start.Line
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
		"#include <bpf/bpf_core_read.h>",
		"hzn_current_ppid",
		"hzn_current_uid",
		"hzn_current_comm",
		"hzn_ktime_get_ns",
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
		"struct hzn_type_Count {",
		`_Static_assert(sizeof(struct hzn_type_Count) == 4, "horizon: struct Count size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_Count, seen) == 0, "horizon: struct Count.seen offset mismatch");`,
		"static __always_inline long Counts_update(__u32 key, struct hzn_type_Count value)",
		"struct hzn_type_Count state = (struct hzn_type_Count){ .seen = pid };",
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

func TestEmitUsesAuthoredContextParamName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xdp.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@xdp
func Pass(packet xdp.Context) i32 {
    if eth := xdp.eth(packet); eth != nil {
        return xdp.Pass
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, needle := range []string{
		"int Pass(struct xdp_md *packet) {",
		"(void)packet;",
		"hzn_xdp_eth(packet)",
	} {
		if !strings.Contains(out.Code, needle) {
			t.Fatalf("generated C missing %q:\n%s", needle, out.Code)
		}
	}
	if strings.Contains(out.Code, "int Pass(struct xdp_md *ctx) {") {
		t.Fatalf("generated C ignored authored context parameter:\n%s", out.Code)
	}
}

func TestEmitMapMaxEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maps.hzn")
	if err := os.WriteFile(path, []byte(`package probes

const CountEntries = 4096

type Event struct {
    pid u32
}

@max_entries(4096)
map Counts hash[u32, u32]

@max_entries(CountEntries)
map ConstCounts hash[u32, u32]

@max_entries(0x40000)
map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := compiler.AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"__uint(max_entries, 4096);",
		"__uint(max_entries, 0x40000);",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	if strings.Contains(out.Code, "__uint(max_entries, CountEntries);") || strings.Contains(out.Code, "__uint(max_entries, hzn_const_CountEntries);") {
		t.Fatalf("generated C did not resolve const-backed max_entries:\n%s", out.Code)
	}
	if strings.Contains(out.Code, "__uint(max_entries, 1024);") || strings.Contains(out.Code, "__uint(max_entries, 1 << 24);") {
		t.Fatalf("generated C kept default map sizing:\n%s", out.Code)
	}
}

func TestEmitPerCPUAndLRUMapDefinitionsAndWrappers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "percpu.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u64
}

@max_entries(128)
map Counts percpu_hash[u32, Count]

map Slots percpu_array[u32, u64]

@max_entries(64)
map Recent lru_hash[u32, Count]

@max_entries(64)
map RecentByCPU lru_percpu_hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, Count{seen: u64(pid)}) != 0 {
        return 0
    }

    count := Counts.lookup(pid)
    if count == nil {
        return 0
    }
    count.seen = count.seen + 1

    if Slots.update(0, 1) != 0 {
        return 0
    }

    if Recent.update(pid, Count{seen: 1}) != 0 {
        return 0
    }
    recent := Recent.lookup(pid)
    if recent == nil {
        return 0
    }
    recent.seen = recent.seen + 1

    if RecentByCPU.update(pid, Count{seen: 1}) != 0 {
        return 0
    }

    if Counts.delete(pid) != 0 {
        return 0
    }
    if Recent.delete(pid) != 0 {
        return 0
    }
    if RecentByCPU.delete(pid) != 0 {
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"__uint(type, BPF_MAP_TYPE_PERCPU_HASH);",
		"__uint(max_entries, 128);",
		"__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);",
		"__uint(type, BPF_MAP_TYPE_LRU_HASH);",
		"__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);",
		"static __always_inline struct hzn_type_Count *Counts_lookup(__u32 key)",
		"static __always_inline long Counts_update(__u32 key, struct hzn_type_Count value)",
		"static __always_inline long Counts_delete(__u32 key)",
		"static __always_inline long Slots_update(__u32 key, __u64 value)",
		"static __always_inline struct hzn_type_Count *Recent_lookup(__u32 key)",
		"static __always_inline long Recent_update(__u32 key, struct hzn_type_Count value)",
		"static __always_inline long Recent_delete(__u32 key)",
		"static __always_inline long RecentByCPU_update(__u32 key, struct hzn_type_Count value)",
		"static __always_inline long RecentByCPU_delete(__u32 key)",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
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
		`_Static_assert(sizeof(struct hzn_type_LayoutEvent) == 16, "horizon: struct LayoutEvent size mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_LayoutEvent, tag) == 0, "horizon: struct LayoutEvent.tag offset mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_LayoutEvent, pid) == 4, "horizon: struct LayoutEvent.pid offset mismatch");`,
		`_Static_assert(__builtin_offsetof(struct hzn_type_LayoutEvent, ports) == 8, "horizon: struct LayoutEvent.ports offset mismatch");`,
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

const FirstSeen u32 = 1

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
		"static const __u32 hzn_const_FirstSeen = 1;",
		"if (Counts_update(pid, hzn_const_FirstSeen) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitEnumConstants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdict.hzn")
	if err := os.WriteFile(path, []byte(`package probes

enum Verdict i32 {
    VerdictPass = 0
    VerdictDrop = 1
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() == 0 {
        return VerdictPass
    }
    return VerdictDrop
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
		"static const __s32 hzn_const_VerdictPass = 0;",
		"static const __s32 hzn_const_VerdictDrop = 1;",
		"return hzn_const_VerdictPass;",
		"return hzn_const_VerdictDrop;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitTypedVarDeclarations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vars.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u64
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid u32 = bpf.current_pid()
    var count Count = Count{seen: 1}
    for var i u32 = 0; i < 4; i++ {
        pid = pid + i
    }
    if Counts.update(pid, count) != 0 {
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
		"__u32 pid = hzn_current_pid();",
		"struct hzn_type_Count count = (struct hzn_type_Count){ .seen = 1 };",
		"for (__u32 i = 0; i < 4; i++) {",
		"if (Counts_update(pid, count) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitSwitchStatements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "switch.hzn")
	if err := os.WriteFile(path, []byte(`package probes

enum Verdict i32 {
    VerdictPass = 2
    VerdictDrop = 1
}

func Normalize(verdict i32) i32 {
    switch verdict {
    case VerdictDrop:
        return VerdictDrop
    default:
        return VerdictPass
    }
}

@xdp
func DropWeb(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    switch xdp.ntohs(tcp.dst_port) {
    case 80, 443:
        return xdp.Drop
    default:
        return xdp.Pass
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
		"switch (verdict) {",
		"case 1:",
		"return hzn_const_VerdictDrop;",
		"switch (bpf_ntohs(tcp->dst_port)) {",
		"case 80:",
		"case 443:",
		"return XDP_DROP;",
		"default: {",
		"break;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	if strings.Contains(out.Code, "case hzn_const_VerdictDrop:") {
		t.Fatalf("generated C used static const as case label:\n%s", out.Code)
	}
}

func TestEmitNegativeSignedIntegerLiterals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signed.hzn")
	if err := os.WriteFile(path, []byte(`package probes

const Negative i32 = -1

type Ret struct {
    rc    i64
    small i8
    code  i32
}

map Results hash[u32, Ret]

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    neg := -rc
    if neg < -1 {
        return Negative
    }
    if Results.update(1, Ret{rc: -1, small: -128, code: Negative}) != 0 {
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static const __s32 hzn_const_Negative = -1;",
		"__s64 neg = -rc;",
		"if (neg < -1) {",
		"return hzn_const_Negative;",
		"if (Results_update(1, (struct hzn_type_Ret){ .rc = -1, .small = -128, .code = hzn_const_Negative }) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitBoolLiteralsAndConsts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flags.hzn")
	if err := os.WriteFile(path, []byte(`package probes

const ShouldTrace bool = true

type Flags struct {
    active bool
}

map FlagsByPID hash[u32, Flags]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    active := true
    if ShouldTrace && !false && active {
        if FlagsByPID.update(pid, Flags{active: active}) != 0 {
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
		"#include <stdbool.h>",
		"static const bool hzn_const_ShouldTrace = true;",
		"bool active = true;",
		"if ((hzn_const_ShouldTrace && !false) && active) {",
		"if (FlagsByPID_update(pid, (struct hzn_type_Flags){ .active = active }) != 0) {",
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
		"static const __u64 hzn_const_Mask = 0x0f;",
		"__u32 bucket = (pid & hzn_const_Mask) + 1;",
		"if ((bucket != 0) && (pid > 0)) {",
		"if (Counts_update(bucket, pid) != 0) {",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitExplicitIntegerScalarConversions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

type Count struct {
    pid64 u64
    port  u16
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    pid64 := u64(pid)
    port := u16(pid & 0xffff)
    if Counts.update(pid, Count{pid64: pid64, port: port}) != 0 {
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
		"__u64 pid64 = (__u64)(pid);",
		"__u16 port = (__u16)(pid & 0xffff);",
		"if (Counts_update(pid, (struct hzn_type_Count){ .pid64 = pid64, .port = port }) != 0) {",
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
		"struct hzn_type_Count *count = Counts_lookup(pid);",
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

func TestEmitProbeContextHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Event struct {
    dfd i32
    path [256]u8
    rc  i64
}

map Events ringbuf[Event]

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    event.dfd = i32(kprobe.arg1(ctx))
    if bpf.probe_read_user_str(&event.path, kprobe.arg2(ctx)) < 0 {
        Events.discard(event)
        return 0
    }
    Events.submit(event)
    return 0
}

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    if rc < 0 {
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static __always_inline __u64 hzn_kprobe_arg1(struct pt_regs *ctx)",
		"return (__u64)PT_REGS_PARM1(ctx);",
		"static __always_inline __u64 hzn_kprobe_arg2(struct pt_regs *ctx)",
		"return (__u64)PT_REGS_PARM2(ctx);",
		"static __always_inline long hzn_probe_read_user_str(void *dst, __u32 size, const void *unsafe_ptr)",
		"return bpf_probe_read_user_str(dst, size, unsafe_ptr);",
		"static __always_inline __s64 hzn_kretprobe_ret(struct pt_regs *ctx)",
		"return (__s64)PT_REGS_RC(ctx);",
		"event->dfd = (__s32)(hzn_kprobe_arg1(ctx));",
		"if (hzn_probe_read_user_str(&event->path, sizeof(event->path), (const void *)(long)hzn_kprobe_arg2(ctx)) < 0) {",
		"Events_discard(event);",
		"__s64 rc = hzn_kretprobe_ret(ctx);",
		`SEC("kretprobe/do_sys_openat2")`,
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	if strings.Contains(out.Code, "hzn_kprobe_arg3") {
		t.Fatalf("generated C contains unused arg3 helper:\n%s", out.Code)
	}
}

func TestEmitTCProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tc.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@tc("egress")
func PassEgress(ctx tc.Context) i32 {
    return tc.OK
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
		"#define TC_ACT_OK 0",
		`SEC("tc/egress")`,
		"int PassEgress(struct __sk_buff *ctx) {",
		"return TC_ACT_OK;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitCgroupConnectProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connect.hzn")
	if err := os.WriteFile(path, []byte(`package probes

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
    if cgroup.src_ip4(ctx) == cgroup.ip4(0, 0, 0, 0) {
        return cgroup.Allow
    }
    if (cgroup.dst_port(ctx) == 25) && (cgroup.dst_ip4(ctx) != cgroup.ip4(127, 0, 0, 1)) {
        return cgroup.Deny
    }
    return cgroup.Allow
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
		"#define HZN_CGROUP_ALLOW 1",
		"#define HZN_CGROUP_PROTOCOL_TCP 6",
		"static __always_inline __u32 hzn_cgroup_family(struct bpf_sock_addr *ctx)",
		"static __always_inline __u32 hzn_cgroup_sock_type(struct bpf_sock_addr *ctx)",
		"static __always_inline __u32 hzn_cgroup_protocol(struct bpf_sock_addr *ctx)",
		"static __always_inline __u16 hzn_cgroup_dst_port(struct bpf_sock_addr *ctx)",
		"static __always_inline __u32 hzn_cgroup_dst_ip4(struct bpf_sock_addr *ctx)",
		"static __always_inline __u32 hzn_cgroup_src_ip4(struct bpf_sock_addr *ctx)",
		`SEC("cgroup/connect4")`,
		"int BlockSMTP(struct bpf_sock_addr *ctx) {",
		"if (hzn_cgroup_family(ctx) != HZN_CGROUP_FAMILY_IPV4) {",
		"if (hzn_cgroup_sock_type(ctx) != HZN_CGROUP_SOCK_STREAM) {",
		"if (hzn_cgroup_protocol(ctx) != HZN_CGROUP_PROTOCOL_TCP) {",
		"hzn_cgroup_src_ip4(ctx) == (((__u32)(0) << 24) | ((__u32)(0) << 16) | ((__u32)(0) << 8) | (__u32)(0))",
		"hzn_cgroup_dst_port(ctx) == 25",
		"hzn_cgroup_dst_ip4(ctx) != (((__u32)(127) << 24) | ((__u32)(0) << 16) | ((__u32)(0) << 8) | (__u32)(1))",
		"return HZN_CGROUP_DENY;",
		"return HZN_CGROUP_ALLOW;",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}

func TestEmitLSMProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lsm.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@lsm("file_open")
func DenyFileOpen(ctx lsm.Context) i32 {
    return lsm.Deny
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
		"#define HZN_LSM_ALLOW 0",
		"#define HZN_LSM_DENY (-EPERM)",
		`SEC("lsm/file_open")`,
		"int DenyFileOpen(void *ctx) {",
		"return HZN_LSM_DENY;",
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

func TestEmitRejectsPointerDereference(t *testing.T) {
	out, err := Emit(ir.Program{
		Functions: []ir.Function{{
			Name:    "Bad",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Name: "tracepoint/sched/sched_process_exec"},
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "expr",
					Expr: &ir.Expr{
						Kind:    "unary",
						Op:      "*",
						Operand: &ir.Expr{Kind: "ident", Name: "ptr"},
					},
				}},
			}},
		}},
	})
	if err == nil {
		t.Fatalf("Emit succeeded, code:\n%s", out.Code)
	}
	if out.Code != "" {
		t.Fatalf("Emit returned code for pointer dereference:\n%s", out.Code)
	}
	if !strings.Contains(err.Error(), `unsupported expression kind "unary *"`) {
		t.Fatalf("Emit error = %v, want unsupported unary pointer dereference", err)
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
