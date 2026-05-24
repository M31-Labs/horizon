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
		"../testdata/invalid/packet_unproven_read.hzn":       "HZN2600",
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

func TestAnalyzeAllowsIntegerConstInExpressions(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const FirstSeen = 1

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    Counts.update(pid, FirstSeen)
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 1 || result.Program.Constants[0].Name != "FirstSeen" {
		t.Fatalf("constants = %#v, want FirstSeen", result.Program.Constants)
	}
}

func TestAnalyzeRejectsNonIntegerConst(t *testing.T) {
	result := analyzeSource(t, "const.hzn", `package probes

const Protocol = xdp.IPProtoTCP

@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN1103")
}

func TestAnalyzeAllowsTypedIntegerAndBooleanOperators(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const Mask = 0x0f

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    bucket := (pid & Mask) + 1
    if bucket != 0 && pid > 0 {
        Counts.update(bucket, pid)
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsNonBoolCondition(t *testing.T) {
	result := analyzeSource(t, "bad_condition.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1443")
}

func TestAnalyzeXDPProgramPasses(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@capability("kernel.network.xdp.drop")
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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramXDP {
		t.Fatalf("functions = %#v, want one XDP function", result.Program.Functions)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Section != "xdp" || manifest.Programs[0].Kind != "xdp" {
		t.Fatalf("program manifest = %#v, want xdp section", manifest.Programs)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Section != "xdp" || manifest.Capabilities[0].Danger != "drop" {
		t.Fatalf("capability manifest = %#v, want xdp drop capability section", manifest.Capabilities)
	}
}

func TestAnalyzeRejectsXDPHelperUnavailable(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropAll(ctx xdp.Context) i32 {
    bpf.current_pid()
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN2300")
}

func TestAnalyzeRejectsXDPWrongContext(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropAll(ctx tracepoint.Exec) i32 {
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN1308")
}

func TestAnalyzeKprobeProgramPasses(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@capability("kernel.file.open.observe")
@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    bpf.current_pid()
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramKprobe {
		t.Fatalf("functions = %#v, want one kprobe function", result.Program.Functions)
	}
	if result.Program.Functions[0].Section.Attach != "do_sys_openat2" {
		t.Fatalf("attach = %q, want do_sys_openat2", result.Program.Functions[0].Section.Attach)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Section != "kprobe/do_sys_openat2" || manifest.Programs[0].Kind != "kprobe" {
		t.Fatalf("program manifest = %#v, want kprobe section", manifest.Programs)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Section != "kprobe/do_sys_openat2" || manifest.Capabilities[0].Danger != "observe" {
		t.Fatalf("capability manifest = %#v, want kprobe observe capability", manifest.Capabilities)
	}
}

func TestAnalyzeKretprobeProgramPasses(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramKretprobe {
		t.Fatalf("functions = %#v, want one kretprobe function", result.Program.Functions)
	}
}

func TestAnalyzeRejectsKprobeWrongContext(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

@kprobe("do_sys_openat2")
func OnOpen(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1308")
}

func TestAnalyzeRejectsUnknownXDPAction(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropAll(ctx xdp.Context) i32 {
    return xdp.Unknown
}
`)
	requireDiagnosticCode(t, result, "HZN1434")
}

func TestAnalyzeRejectsPacketHeaderDereferenceWithoutNilCheck(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if xdp.ntohs(tcp.dst_port) == 443 {
        return xdp.Drop
    }
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN2600")
}

func TestAnalyzeRejectsNtohsNonU16Argument(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    ip := xdp.ipv4(ctx)
    if ip == nil {
        return xdp.Pass
    }
    if xdp.ntohs(ip.protocol) == 6 {
        return xdp.Drop
    }
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN1437")
}

func TestAnalyzeUDPPacketHeaderPasses(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropDNS(ctx xdp.Context) i32 {
    udp := xdp.udp(ctx)
    if udp == nil {
        return xdp.Pass
    }
    if xdp.ntohs(udp.dst_port) == 53 {
        return xdp.Drop
    }
    return xdp.Pass
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
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
