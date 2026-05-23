package compiler

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func TestAnalyzeExecwatchPasses(t *testing.T) {
	result, err := AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if result.Program.Package != "probes" {
		t.Fatalf("package = %q, want probes", result.Program.Package)
	}
	if len(result.Program.Functions) != 1 || len(result.Program.Maps) != 1 || len(result.Program.Capabilities) != 1 {
		t.Fatalf("program = %#v, want one function, map, and capability", result.Program)
	}
}

func TestAnalyzeInvalidRingbufPrograms(t *testing.T) {
	tests := map[string]string{
		"../testdata/invalid/ringbuf_missing_nil_check.hzn":  "HZN2100",
		"../testdata/invalid/ringbuf_write_after_submit.hzn": "HZN2103",
		"../testdata/invalid/ringbuf_double_submit.hzn":      "HZN2102",
		"../testdata/invalid/ringbuf_live_on_return.hzn":     "HZN2104",
		"../testdata/invalid/unbounded_loop.hzn":             "HZN2200",
		"../testdata/invalid/current_comm_bad_arg.hzn":       "HZN1415",
		"../testdata/invalid/unknown_event_field.hzn":        "HZN1406",
	}
	for path, code := range tests {
		result, err := AnalyzePath(path)
		if err != nil {
			t.Fatalf("AnalyzePath(%s): %v", path, err)
		}
		if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool {
			return d.Code == code
		}) {
			t.Fatalf("AnalyzePath(%s) diagnostics = %#v, want %s", path, result.Diagnostics, code)
		}
	}
}

func TestAnalyzeBoundedForLoopPasses(t *testing.T) {
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
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsNonConstantLoopBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loop.hzn")
	if err := os.WriteFile(path, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    limit := bpf.current_pid()
    for i := 0; i < limit; i++ {
        bpf.current_pid()
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool { return d.Code == "HZN2202" }) {
		t.Fatalf("diagnostics = %#v, want HZN2202", result.Diagnostics)
	}
}

func TestAnalyzeHashLookupRequiresNilCheckAndTracksManifestAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counts.hzn")
	if err := os.WriteFile(path, []byte(`package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@capability("kernel.process.exec.count")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    if count == nil {
        return 0
    }
    count.seen = bpf.current_pid()
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].Kind != ir.MapKindHash {
		t.Fatalf("maps = %#v, want one hash map", result.Program.Maps)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	access := manifest.Capabilities[0].Maps
	if !slices.Contains(access.Read, "Counts") || !slices.Contains(access.Write, "Counts") {
		t.Fatalf("map access = %#v, want read and write Counts", access)
	}
}

func TestAnalyzeRejectsHashLookupDereferenceWithoutNilCheck(t *testing.T) {
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
    count.seen = 1
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool { return d.Code == "HZN2500" }) {
		t.Fatalf("diagnostics = %#v, want HZN2500", result.Diagnostics)
	}
}

func TestAnalyzeAllowsHashLookupNonNilBranch(t *testing.T) {
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
    if count != nil {
        count.seen = 1
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsStructLiteralMapUpdate(t *testing.T) {
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
    Counts.update(pid, Count{seen: pid})
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsUnknownStructLiteralField(t *testing.T) {
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
    Counts.update(pid, Count{missing: pid})
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool { return d.Code == "HZN1427" }) {
		t.Fatalf("diagnostics = %#v, want HZN1427", result.Diagnostics)
	}
}

func TestAnalyzeRejectsFixedArrayValueCopies(t *testing.T) {
	tests := map[string]string{
		"local copy": `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    comm := event.comm
    Events.discard(event)
    return 0
}
`,
		"local pointer alias": `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    comm := &event.comm
    Events.discard(event)
    return 0
}
`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "array.hzn", source)
			requireDiagnosticCode(t, result, "HZN1430")
		})
	}
}

func TestAnalyzeRejectsFixedArrayFieldAssignment(t *testing.T) {
	result := analyzeSource(t, "array.hzn", `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    event.comm = event.comm
    Events.discard(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1431")
}

func TestAnalyzeRejectsFixedArrayStructLiteralField(t *testing.T) {
	result := analyzeSource(t, "array.hzn", `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    copy := Event{comm: event.comm}
    Events.discard(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1433")
}

func TestAnalyzeTreatsHelperArrayWritesAsRingbufWrites(t *testing.T) {
	tests := map[string]string{
		"missing nil check": `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    bpf.current_comm(&event.comm)
    if event == nil {
        return 0
    }
    Events.submit(event)
    return 0
}
`,
		"after submit": `package probes

type Event struct {
    comm [16]u8
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    Events.submit(event)
    bpf.current_comm(&event.comm)
    return 0
}
`,
	}
	want := map[string]string{
		"missing nil check": "HZN2100",
		"after submit":      "HZN2103",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "array.hzn", source)
			requireDiagnosticCode(t, result, want[name])
		})
	}
}

func analyzeSource(t *testing.T, name string, source string) *Result {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	return result
}

func requireDiagnosticCode(t *testing.T, result *Result, code string) {
	t.Helper()
	if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool { return d.Code == code }) {
		t.Fatalf("diagnostics = %#v, want %s", result.Diagnostics, code)
	}
}
