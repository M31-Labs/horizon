package compiler

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/emitc"
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

func TestAnalyzeMultiFilePackageUsesSharedDeclarations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a_program.hzn"), []byte(`package probes

@capability("kernel.process.exec.observe")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    event.pid = bpf.current_pid()
    Events.submit(event)
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile program: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z_events.hzn"), []byte(`package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]
`), 0o600); err != nil {
		t.Fatalf("WriteFile events: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Structs) != 1 || result.Program.Structs[0].Name != "Event" {
		t.Fatalf("structs = %#v, want Event from package file", result.Program.Structs)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].Name != "Events" {
		t.Fatalf("maps = %#v, want Events from package file", result.Program.Maps)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	capability := manifest.Capabilities[0]
	if capability.Emits != "Event" || !slices.Contains(capability.Maps.Events, "Events") {
		t.Fatalf("capability = %#v, want Event emitted through Events", capability)
	}
}

func TestAnalyzeCapabilityAliasResolvesManifestName(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability ExecObserve danger observe = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	if got, want := manifest.Capabilities[0].Name, "kernel.process.exec.observe"; got != want {
		t.Fatalf("capability name = %q, want %q", got, want)
	}
	if got, want := manifest.Capabilities[0].Danger, "observe"; got != want {
		t.Fatalf("capability danger = %q, want %q", got, want)
	}
}

func TestAnalyzeCapabilityAliasExplicitDangerRaisesManifestDanger(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability DropCapability danger drop = "kernel.network.xdp.drop"

@capability(DropCapability)
@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Pass
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	if got, want := manifest.Capabilities[0].Danger, "drop"; got != want {
		t.Fatalf("capability danger = %q, want %q", got, want)
	}
}

func TestAnalyzeCapabilityAliasDangerCannotUnderstateInferredDanger(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability ObserveCapability danger observe = "kernel.network.xdp.observe"

@capability(ObserveCapability)
@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Drop
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	if got, want := manifest.Capabilities[0].Danger, "drop"; got != want {
		t.Fatalf("capability danger = %q, want inferred floor %q", got, want)
	}
}

func TestAnalyzeCapabilityNameDangerSuffixFloorsManifestDanger(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

@capability("kernel.process.exec.block")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v, want one", manifest.Capabilities)
	}
	if got, want := manifest.Capabilities[0].Danger, "block"; got != want {
		t.Fatalf("capability danger = %q, want capability-name floor %q", got, want)
	}
}

func TestAnalyzeCapabilityAliasCanBeSharedAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a_capability.hzn"), []byte(`package probes

capability ExecObserve danger observe = "kernel.process.exec.observe"
`), 0o600); err != nil {
		t.Fatalf("WriteFile capability: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z_program.hzn"), []byte(`package probes

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile program: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if got := result.Program.Capabilities[0].Name; got != "kernel.process.exec.observe" {
		t.Fatalf("capability name = %q, want alias value", got)
	}
}

func TestAnalyzeRejectsUnknownCapabilityAlias(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1321")
}

func TestAnalyzeRejectsEmptyCapabilityAlias(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability ExecObserve = ""

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1322")
}

func TestAnalyzeRejectsUnsupportedCapabilityDanger(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability ExecObserve danger destroy = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1323")
}

func TestAnalyzeRejectsCapabilityAliasDangerBelowNameSuffix(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

capability ExecBlock danger observe = "kernel.process.exec.block"

@capability(ExecBlock)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1324")
}

func TestAnalyzeRejectsCapabilityNamespaceMismatch(t *testing.T) {
	result := analyzeSource(t, "capability.hzn", `package probes

@capability("kernel.process.exec.observe")
@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Pass
}
`)
	diagnostic := requireDiagnosticCode(t, result, "HZN2502")
	if diagnostic.Primary.Start.Line != 3 {
		t.Fatalf("primary span = %#v, want @capability line", diagnostic.Primary)
	}
}

func TestAnalyzeRejectsDuplicateDeclarationsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.hzn"), []byte(`package probes

type Event struct {
    pid u32
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.hzn"), []byte(`package probes

type Event struct {
    uid u32
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile b: %v", err)
	}
	result, err := AnalyzePath(dir)
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	requireDiagnosticCode(t, result, "HZN1002")
}

func TestAnalyzeRejectsDefaultBindgenNameCollision(t *testing.T) {
	result := analyzeSource(t, "bindings.hzn", `package probes

type load_objects struct {
    pid u32
}

map Events ringbuf[load_objects]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	d := requireDiagnosticCode(t, result, "HZN3200")
	if d.Primary.IsZero() || d.Primary.Start.Line != 3 {
		t.Fatalf("diagnostic primary = %#v, want struct declaration on line 3", d.Primary)
	}
}

func TestAnalyzeAllowsSafeLiteralArithmetic(t *testing.T) {
	result := analyzeSource(t, "arithmetic.hzn", `package probes

const Shift u32 = 31
const One u32 = 1

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    value := u32(1) << Shift
    other := value / One
    small := u8(u32(255))
    if other % 3 == 0 && small == 255 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsScalarUserHelpers(t *testing.T) {
	result := analyzeSource(t, "helpers.hzn", `package probes

func should_count(pid u32) bool {
    return pid != 0
}

func normalize_pid(pid u32) u32 {
    if should_count(pid) {
        return pid
    }
    return 1
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := normalize_pid(bpf.current_pid())
    if should_count(pid) {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 3 {
		t.Fatalf("functions = %#v, want two helpers and one eBPF program", result.Program.Functions)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Name != "OnExec" {
		t.Fatalf("manifest programs = %#v, want only the eBPF entrypoint", manifest.Programs)
	}
	out, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static __always_inline bool hzn_fn_should_count(__u32 pid)",
		"static __always_inline __u32 hzn_fn_normalize_pid(__u32 pid)",
		"pid = hzn_fn_normalize_pid(hzn_current_pid())",
		"if (hzn_fn_should_count(pid))",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
	bindings, err := bindgen.Generate(result.Program, "bindings")
	if err != nil {
		t.Fatalf("bindgen: %v", err)
	}
	if strings.Contains(bindings, "ShouldCount *ebpf.Program") || strings.Contains(bindings, "NormalizePid *ebpf.Program") {
		t.Fatalf("bindings expose helper functions as programs:\n%s", bindings)
	}
	if !strings.Contains(bindings, "OnExec *ebpf.Program") {
		t.Fatalf("bindings missing entrypoint program:\n%s", bindings)
	}
}

func TestAnalyzeRejectsEntrypointCalls(t *testing.T) {
	result := analyzeSource(t, "helpers.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func Other(ctx tracepoint.Exec) i32 {
    return 0
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return Other(ctx)
}
`)
	requireDiagnosticCode(t, result, "HZN1501")
}

func TestAnalyzeRejectsRecursiveUserHelpers(t *testing.T) {
	result := analyzeSource(t, "helpers.hzn", `package probes

func a(pid u32) u32 {
    return b(pid)
}

func b(pid u32) u32 {
    return a(pid)
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := a(bpf.current_pid())
    if pid == 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1503")
}

func TestAnalyzeRejectsNonScalarUserHelperSignatures(t *testing.T) {
	result := analyzeSource(t, "helpers.hzn", `package probes

type Event struct {
    pid u32
}

func event(pid u32) Event {
    return Event{pid: pid}
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1320")
}

func TestAnalyzeRejectsUserHelperReturnMismatch(t *testing.T) {
	result := analyzeSource(t, "helpers.hzn", `package probes

func bad(pid u32) bool {
    return pid
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1505")
}

func TestAnalyzeAllowsGuardedDynamicDivisor(t *testing.T) {
	result := analyzeSource(t, "divisor.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    denom := bpf.current_pid()
    if denom == 0 {
        return 0
    }
    value := u32(100) / denom
    if value == 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsBranchGuardedDynamicDivisor(t *testing.T) {
	result := analyzeSource(t, "divisor.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    denom := bpf.current_pid()
    if denom != 0 {
        value := u32(100) % denom
        if value == 0 {
            return 0
        }
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsGuardedDynamicShiftCount(t *testing.T) {
	result := analyzeSource(t, "shift.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    shift := bpf.current_pid()
    if shift >= 32 {
        return 0
    }
    value := u32(1) << shift
    if value == 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsBranchGuardedDynamicShiftCount(t *testing.T) {
	result := analyzeSource(t, "shift.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    shift := bpf.current_pid()
    if shift < 32 {
        value := u32(1) << shift
        if value == 0 {
            return 0
        }
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsSignedGuardedDynamicShiftCount(t *testing.T) {
	result := analyzeSource(t, "shift.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    shift := i32(bpf.current_pid())
    if shift >= 0 && shift < 32 {
        value := u32(1) << shift
        if value == 0 {
            return 0
        }
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeReportsParseDiagnostic(t *testing.T) {
	result := analyzeSource(t, "bad.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if {
        return 0
    }
}
`)
	requireDiagnosticCode(t, result, "HZN0100")
	if len(result.Program.Functions) != 0 {
		t.Fatalf("functions = %#v, want none when parsing fails", result.Program.Functions)
	}
	if len(result.Files) != 1 || len(result.Files[0].Diagnostics) != 1 {
		t.Fatalf("file diagnostics = %#v, want one parse diagnostic", result.Files)
	}
	if result.Files[0].Diagnostics[0].Primary.File == "" {
		t.Fatalf("parse diagnostic primary span is empty: %#v", result.Files[0].Diagnostics[0])
	}
}

func TestAnalyzeInvalidRingbufPrograms(t *testing.T) {
	tests := map[string]string{
		"../testdata/invalid/ringbuf_missing_nil_check.hzn":              "HZN2100",
		"../testdata/invalid/ringbuf_write_after_submit.hzn":             "HZN2103",
		"../testdata/invalid/ringbuf_double_submit.hzn":                  "HZN2102",
		"../testdata/invalid/ringbuf_live_on_return.hzn":                 "HZN2104",
		"../testdata/invalid/unbounded_loop.hzn":                         "HZN2200",
		"../testdata/invalid/current_comm_bad_arg.hzn":                   "HZN1415",
		"../testdata/invalid/unknown_event_field.hzn":                    "HZN1406",
		"../testdata/invalid/packet_unproven_read.hzn":                   "HZN2600",
		"../testdata/invalid/stack_too_large.hzn":                        "HZN2700",
		"../testdata/invalid/missing_return.hzn":                         "HZN1445",
		"../testdata/invalid/map_update_ignored.hzn":                     "HZN1446",
		"../testdata/invalid/map_lookup_alias.hzn":                       "HZN1447",
		"../testdata/invalid/ringbuf_reservation_alias.hzn":              "HZN1447",
		"../testdata/invalid/packet_header_alias.hzn":                    "HZN1447",
		"../testdata/invalid/xdp_raw_return.hzn":                         "HZN1448",
		"../testdata/invalid/cgroup_ip4_bad_octet.hzn":                   "HZN1469",
		"../testdata/invalid/raw_scalar_address.hzn":                     "HZN1472",
		"../testdata/invalid/pointer_deref.hzn":                          "HZN1473",
		"../testdata/invalid/bare_return.hzn":                            "HZN1476",
		"../testdata/invalid/division_by_zero.hzn":                       "HZN1478",
		"../testdata/invalid/modulo_by_zero.hzn":                         "HZN1478",
		"../testdata/invalid/const_division_by_zero.hzn":                 "HZN1478",
		"../testdata/invalid/shift_out_of_range.hzn":                     "HZN1479",
		"../testdata/invalid/negative_shift_count.hzn":                   "HZN1479",
		"../testdata/invalid/const_shift_out_of_range.hzn":               "HZN1479",
		"../testdata/invalid/huge_shift_count.hzn":                       "HZN1479",
		"../testdata/invalid/conversion_literal_out_of_range.hzn":        "HZN1470",
		"../testdata/invalid/dynamic_divisor_missing_guard.hzn":          "HZN1480",
		"../testdata/invalid/reassigned_divisor_loses_nonzero_proof.hzn": "HZN1480",
		"../testdata/invalid/constant_assignment.hzn":                    "HZN1481",
		"../testdata/invalid/dynamic_shift_missing_bound.hzn":            "HZN1482",
		"../testdata/invalid/reassigned_shift_loses_bound.hzn":           "HZN1482",
		"../testdata/invalid/source_pointer_type.hzn":                    "HZN1106",
		"../testdata/invalid/duplicate_struct_field.hzn":                 "HZN1107",
		"../testdata/invalid/recursive_struct.hzn":                       "HZN1108",
		"../testdata/invalid/indirect_recursive_struct.hzn":              "HZN1108",
		"../testdata/invalid/local_redeclare.hzn":                        "HZN1477",
		"../testdata/invalid/local_map_shadow.hzn":                       "HZN1477",
		"../testdata/invalid/local_namespace_shadow.hzn":                 "HZN1477",
		"../testdata/invalid/top_level_namespace_shadow.hzn":             "HZN1004",
		"../testdata/invalid/ringbuf_scalar_value.hzn":                   "HZN1209",
		"../testdata/invalid/struct_compiler_owned_field.hzn":            "HZN1110",
		"../testdata/invalid/map_compiler_owned_value.hzn":               "HZN1110",
		"../testdata/invalid/map_compiler_owned_key.hzn":                 "HZN1110",
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

func TestAnalyzeAllowsStackReuseAcrossExclusiveBranches(t *testing.T) {
	result := analyzeSource(t, "stack.hzn", `package probes

type Big struct {
    payload [300]u8
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() != 0 {
        left := Big{}
    } else {
        right := Big{}
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsSequentialLargeStackLocals(t *testing.T) {
	result := analyzeSource(t, "stack.hzn", `package probes

type Big struct {
    payload [300]u8
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    first := Big{}
    second := Big{}
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN2700")
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

func TestAnalyzeBoundedForLoopAcceptsConstBound(t *testing.T) {
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

func TestAnalyzeMapMaxEntriesPassesAndLowersToIR(t *testing.T) {
	result := analyzeSource(t, "maps.hzn", `package probes

const CountEntries u32 = 4096
const RingbufBytes = 262144

type Event struct {
    pid u32
}

@max_entries(4096)
map Counts hash[u32, u32]

@max_entries(CountEntries)
map ConstCounts hash[u32, u32]

@max_entries(RingbufBytes)
map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Maps) != 3 {
		t.Fatalf("maps = %#v, want three", result.Program.Maps)
	}
	if result.Program.Maps[0].MaxEntries != "4096" || result.Program.Maps[1].MaxEntries != "4096" || result.Program.Maps[2].MaxEntries != "262144" {
		t.Fatalf("maps = %#v, want configured max entries", result.Program.Maps)
	}
}

func TestAnalyzePerCPUAndLRUMapsPassAndTrackManifestAccess(t *testing.T) {
	result := analyzeSource(t, "percpu.hzn", `package probes

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

@capability("kernel.process.exec.count")
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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Maps) != 4 {
		t.Fatalf("maps = %#v, want four", result.Program.Maps)
	}
	if result.Program.Maps[0].Kind != ir.MapKindPerCPUHash || result.Program.Maps[0].MaxEntries != "128" {
		t.Fatalf("map[0] = %#v, want configured percpu hash", result.Program.Maps[0])
	}
	if result.Program.Maps[1].Kind != ir.MapKindPerCPUArray {
		t.Fatalf("map[1] = %#v, want percpu array", result.Program.Maps[1])
	}
	if result.Program.Maps[2].Kind != ir.MapKindLRUHash || result.Program.Maps[2].MaxEntries != "64" {
		t.Fatalf("map[2] = %#v, want configured lru hash", result.Program.Maps[2])
	}
	if result.Program.Maps[3].Kind != ir.MapKindLRUPerCPU || result.Program.Maps[3].MaxEntries != "64" {
		t.Fatalf("map[3] = %#v, want configured lru percpu hash", result.Program.Maps[3])
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Capabilities) != 1 {
		t.Fatalf("manifest capabilities = %#v, want one", manifest.Capabilities)
	}
	access := manifest.Capabilities[0].Maps
	for _, name := range []string{"Counts", "Recent"} {
		if !slices.Contains(access.Read, name) {
			t.Fatalf("map access = %#v, want %s read", access, name)
		}
	}
	for _, name := range []string{"Counts", "Slots", "Recent", "RecentByCPU"} {
		if !slices.Contains(access.Write, name) {
			t.Fatalf("map access = %#v, want %s write", access, name)
		}
	}
}

func TestAnalyzeRejectsInvalidPerCPUMapUse(t *testing.T) {
	tests := map[string]struct {
		source string
		code   string
	}{
		"percpu array key": {
			code: "HZN1204",
			source: `package probes

map Slots percpu_array[u64, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		},
		"percpu array delete": {
			code: "HZN1423",
			source: `package probes

map Slots percpu_array[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if Slots.delete(0) != 0 {
        return 0
    }
    return 0
}
`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "percpu.hzn", test.source)
			requireDiagnosticCode(t, result, test.code)
		})
	}
}

func TestAnalyzeRejectsInvalidMapMaxEntries(t *testing.T) {
	tests := map[string]string{
		"string value": `package probes

@max_entries("4096")
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"zero value": `package probes

@max_entries(0)
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"unknown const": `package probes

@max_entries(CountEntries)
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"bool const": `package probes

const CountEntries = true

@max_entries(CountEntries)
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"ringbuf non power of two": `package probes

type Event struct {
    pid u32
}

@max_entries(3000)
map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"unknown attribute": `package probes

@capacity(4096)
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
		"duplicate attribute": `package probes

@max_entries(4096)
@max_entries(8192)
map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`,
	}
	want := map[string]string{
		"string value":             "HZN1206",
		"zero value":               "HZN1206",
		"unknown const":            "HZN1206",
		"bool const":               "HZN1206",
		"ringbuf non power of two": "HZN1207",
		"unknown attribute":        "HZN1205",
		"duplicate attribute":      "HZN1208",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "maps.hzn", source)
			requireDiagnosticCode(t, result, want[name])
		})
	}
}

func TestAnalyzeRejectsNonStringSectionAttributeValue(t *testing.T) {
	result := analyzeSource(t, "section.hzn", `package probes

const Section = 1

@tracepoint(Section)
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1302")
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

func TestAnalyzeRejectsHashLookupGuardInOnlyOneBranch(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    if pid == 0 {
        if count == nil {
            return 0
        }
    }
    count.seen = pid
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN2500")
}

func TestAnalyzeHashLookupGuardedInBothBranchesPasses(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    if pid == 0 {
        if count == nil {
            return 0
        }
    } else {
        if count == nil {
            return 0
        }
    }
    count.seen = pid
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsTrackedPointerAliases(t *testing.T) {
	tests := map[string]string{
		"map lookup alias": `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    alias := count
    if alias == nil {
        return 0
    }
    alias.seen = 1
    return 0
}
`,
		"map lookup assignment": `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := Counts.lookup(pid)
    count = Counts.lookup(pid)
    if count == nil {
        return 0
    }
    count.seen = 1
    return 0
}
`,
		"ringbuf reservation alias": `package probes

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
`,
		"packet header alias": `package probes

@xdp
func DropIPv4(ctx xdp.Context) i32 {
    eth := xdp.eth(ctx)
    alias := eth
    if alias == nil {
        return xdp.Pass
    }
    if xdp.ntohs(alias.proto) == xdp.EtherTypeIPv4 {
        return xdp.Drop
    }
    return xdp.Pass
}
`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "alias.hzn", source)
			requireDiagnosticCode(t, result, "HZN1447")
		})
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
    if Counts.update(pid, Count{seen: pid}) != 0 {
        return 0
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
    if Counts.update(pid, Count{missing: pid}) != 0 {
        return 0
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
	if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool { return d.Code == "HZN1427" }) {
		t.Fatalf("diagnostics = %#v, want HZN1427", result.Diagnostics)
	}
}

func TestAnalyzeRejectsStoredFallibleMapResult(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    err := Counts.update(pid, Count{seen: pid})
    if err != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1446")
}

func TestAnalyzeRejectsIgnoredFallibleMapDelete(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    Counts.delete(pid)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1446")
}

func TestAnalyzeRejectsFallibleMapResultInArithmetic(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    value := Counts.update(pid, Count{seen: pid}) + 1
    if value != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1446")
}

func TestAnalyzeAllowsIntegerConstInExpressions(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 1 || result.Program.Constants[0].Name != "FirstSeen" {
		t.Fatalf("constants = %#v, want FirstSeen", result.Program.Constants)
	}
}

func TestAnalyzeAllowsTypedIntegerConstInExpressions(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const FirstSeen u64 = 1
const BucketMask u32 = 0x0f

type Count struct {
    seen u64
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    bucket := pid & BucketMask
    if Counts.update(bucket, Count{seen: FirstSeen}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 2 || result.Program.Constants[0].Type.Name != "u64" || result.Program.Constants[1].Type.Name != "u32" {
		t.Fatalf("constants = %#v, want typed FirstSeen u64 and BucketMask u32", result.Program.Constants)
	}
}

func TestAnalyzeAllowsConstGroups(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Bucket = u32

const (
    CountEntries u32 = 128
    FirstSeen u64 = 1
    BucketMask Bucket = 0x0f
)

type Count struct {
    seen u64
}

@max_entries(CountEntries)
map Counts hash[Bucket, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    bucket := pid & BucketMask
    if Counts.update(bucket, Count{seen: FirstSeen}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 3 {
		t.Fatalf("constants = %#v, want three grouped constants", result.Program.Constants)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].MaxEntries != "128" {
		t.Fatalf("maps = %#v, want grouped const max_entries resolved", result.Program.Maps)
	}
	if result.Program.Constants[2].Type.Name != "u32" {
		t.Fatalf("BucketMask type = %#v, want alias lowered to u32", result.Program.Constants[2].Type)
	}
}

func TestAnalyzeRejectsDuplicateConstGroupName(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const (
    CountEntries = 128
    CountEntries = 256
)
`)
	requireDiagnosticCode(t, result, "HZN1002")
}

func TestAnalyzeRejectsEmptyConstGroup(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const (
)
`)
	requireDiagnosticCode(t, result, "HZN1109")
}

func TestAnalyzeAllowsTypedEnumValuesInExpressions(t *testing.T) {
	result := analyzeSource(t, "verdict.hzn", `package probes

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 2 || result.Program.Constants[0].Type.Name != "i32" || result.Program.Constants[1].Name != "VerdictDrop" {
		t.Fatalf("constants = %#v, want typed enum values lowered as constants", result.Program.Constants)
	}
}

func TestAnalyzeAllowsEnumValueForMapMaxEntries(t *testing.T) {
	result := analyzeSource(t, "maps.hzn", `package probes

enum MapSize u32 {
    CountEntries = 4096
}

@max_entries(CountEntries)
map Counts hash[u32, u64]
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].MaxEntries != "4096" {
		t.Fatalf("maps = %#v, want enum-backed max_entries resolved to 4096", result.Program.Maps)
	}
}

func TestAnalyzeAllowsTypedVarDeclarations(t *testing.T) {
	result := analyzeSource(t, "vars.hzn", `package probes

type Count struct {
    seen u64
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid u32 = bpf.current_pid()
    var count Count = Count{seen: 1}
    if Counts.update(pid, count) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsTypedVarForLoopInit(t *testing.T) {
	result := analyzeSource(t, "vars.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var sum u32 = 0
    for var i u32 = 0; i < 4; i++ {
        sum = sum + i
    }
    return i32(sum)
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsVarTypeMismatch(t *testing.T) {
	result := analyzeSource(t, "vars.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid u8 = 256
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsVarResourceAlias(t *testing.T) {
	result := analyzeSource(t, "vars.hzn", `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var event Event = Events.reserve()
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1447")
}

func TestAnalyzeRejectsCompilerOwnedVarType(t *testing.T) {
	result := analyzeSource(t, "vars.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    var tcp xdp.TCP = xdp.tcp(ctx)
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN1483")
}

func TestAnalyzeAllowsScalarTypeAliases(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type Pid = u32
type Port = u16

type Event struct {
    pid Pid
    port Port
}

@max_entries(64)
map Counts hash[Pid, Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid Pid = bpf.current_pid()
    var port Port = 443
    if Counts.update(pid, Event{pid: pid, port: port}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Structs) != 1 || result.Program.Structs[0].Name != "Event" {
		t.Fatalf("structs = %#v, want only Event", result.Program.Structs)
	}
	if got := result.Program.Structs[0].Fields[0].Type.Name; got != "u32" {
		t.Fatalf("Event.pid type = %q, want u32", got)
	}
	if got := result.Program.Structs[0].Fields[1].Type.Name; got != "u16" {
		t.Fatalf("Event.port type = %q, want u16", got)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].Key.Name != "u32" {
		t.Fatalf("maps = %#v, want hash key lowered to u32", result.Program.Maps)
	}
}

func TestAnalyzeAllowsTypeGroups(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type (
    Pid = u32
    Port = u16
    Event struct {
        pid Pid
        port Port
    }
)

@max_entries(64)
map Counts hash[Pid, Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid Pid = bpf.current_pid()
    var port Port = 443
    if Counts.update(pid, Event{pid: pid, port: port}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Structs) != 1 || result.Program.Structs[0].Name != "Event" {
		t.Fatalf("structs = %#v, want only Event", result.Program.Structs)
	}
	if len(result.Program.Maps) != 1 || result.Program.Maps[0].Key.Name != "u32" || result.Program.Structs[0].Fields[1].Type.Name != "u16" {
		t.Fatalf("program = %#v, want aliases lowered through group", result.Program)
	}
}

func TestAnalyzeRejectsDuplicateTypeGroupName(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type (
    Pid = u32
    Pid = u64
)
`)
	requireDiagnosticCode(t, result, "HZN1002")
}

func TestAnalyzeRejectsEmptyTypeGroup(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type (
)
`)
	requireDiagnosticCode(t, result, "HZN1113")
}

func TestAnalyzeRejectsTypeAliasToStruct(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type Event struct {
    pid u32
}

type EventAlias = Event
`)
	requireDiagnosticCode(t, result, "HZN1112")
}

func TestAnalyzeRejectsRecursiveTypeAlias(t *testing.T) {
	result := analyzeSource(t, "aliases.hzn", `package probes

type A = B
type B = A
`)
	requireDiagnosticCode(t, result, "HZN1111")
}

func TestAnalyzeAllowsSwitchStatements(t *testing.T) {
	result := analyzeSource(t, "switch.hzn", `package probes

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsEnumSwitchStatements(t *testing.T) {
	result := analyzeSource(t, "switch.hzn", `package probes

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsSwitchResourceValue(t *testing.T) {
	result := analyzeSource(t, "switch.hzn", `package probes

type Count struct {
    seen u64
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    count := Counts.lookup(1)
    switch count {
    case nil:
        return 0
    default:
        return 0
    }
}
`)
	requireDiagnosticCode(t, result, "HZN1490")
}

func TestAnalyzeRejectsDynamicSwitchCase(t *testing.T) {
	result := analyzeSource(t, "switch.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid u32 = bpf.current_pid()
    switch pid {
    case pid:
        return 0
    default:
        return 0
    }
}
`)
	requireDiagnosticCode(t, result, "HZN1493")
}

func TestAnalyzeRejectsSwitchCaseTypeMismatch(t *testing.T) {
	result := analyzeSource(t, "switch.hzn", `package probes

@xdp
func DropWeb(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    switch xdp.ntohs(tcp.dst_port) {
    case xdp.IPProtoTCP:
        return xdp.Drop
    default:
        return xdp.Pass
    }
}
`)
	requireDiagnosticCode(t, result, "HZN1492")
}

func TestAnalyzeUsesTypedConstWidth(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const Wide u64 = 1

map Counts hash[u32, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, Wide) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1422")
}

func TestAnalyzeAllowsIntegerLiteralBoundaries(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const MaxPort u16 = 65535

map Counts hash[u8, u16]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if Counts.update(255, MaxPort) != 0 {
        return 0
    }
    return 2147483647
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsTypedConstIntegerLiteralOverflow(t *testing.T) {
	result := analyzeSource(t, "const.hzn", `package probes

const BadPort u16 = 70000

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsStructLiteralIntegerOverflow(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

type Count struct {
    port u16
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, Count{port: 70000}) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsMapKeyIntegerOverflow(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

map Counts hash[u8, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if Counts.update(300, 1) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsUntypedConstIntegerOverflow(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

const BadKey = 300

map Counts hash[u8, u32]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if Counts.update(BadKey, 1) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsReturnIntegerOverflow(t *testing.T) {
	result := analyzeSource(t, "returns.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 2147483648
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeAllowsNegativeSignedIntegerLiterals(t *testing.T) {
	result := analyzeSource(t, "signed.hzn", `package probes

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
        return 0
    }
    if Results.update(1, Ret{rc: -1, small: -128, code: Negative}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsNegativeIntegerLiteralOverflow(t *testing.T) {
	result := analyzeSource(t, "signed.hzn", `package probes

type Ret struct {
    small i8
}

map Results hash[u32, Ret]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if Results.update(1, Ret{small: -129}) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsUnsignedNegation(t *testing.T) {
	result := analyzeSource(t, "signed.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    neg := -pid
    if neg != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1471")
}

func TestAnalyzeRejectsIntegerLiteralComparisonOverflow(t *testing.T) {
	result := analyzeSource(t, "compare.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    port := u16(bpf.current_pid())
    if port == 70000 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeAllowsBoolLiteralsAndConsts(t *testing.T) {
	result := analyzeSource(t, "flags.hzn", `package probes

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Constants) != 1 || result.Program.Constants[0].Value.Kind != "bool" {
		t.Fatalf("constants = %#v, want bool ShouldTrace", result.Program.Constants)
	}
}

func TestAnalyzeRejectsTypedConstValueMismatch(t *testing.T) {
	result := analyzeSource(t, "const.hzn", `package probes

const ShouldTrace bool = 1

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1105")
}

func TestAnalyzeRejectsInvalidEnumBackingType(t *testing.T) {
	result := analyzeSource(t, "enum.hzn", `package probes

enum Flag bool {
    FlagOn = 1
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1120")
}

func TestAnalyzeRejectsEnumNonIntegerValue(t *testing.T) {
	result := analyzeSource(t, "enum.hzn", `package probes

enum Flag u32 {
    FlagOn = true
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1122")
}

func TestAnalyzeRejectsEnumValueOutOfRange(t *testing.T) {
	result := analyzeSource(t, "enum.hzn", `package probes

enum Small u8 {
    TooBig = 256
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsNonScalarConstType(t *testing.T) {
	result := analyzeSource(t, "const.hzn", `package probes

const Bad [4]u8 = 1

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1104")
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

func TestAnalyzeRejectsIntegerLiteralAssignedToBool(t *testing.T) {
	result := analyzeSource(t, "flags.hzn", `package probes

type Flags struct {
    active bool
}

map FlagsByPID hash[u32, Flags]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if FlagsByPID.update(pid, Flags{active: 1}) != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1428")
}

func TestAnalyzeRejectsNotOnNonBool(t *testing.T) {
	result := analyzeSource(t, "flags.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if !bpf.current_pid() {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1442")
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
        if Counts.update(bucket, pid) != 0 {
            return 0
        }
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsExplicitIntegerScalarConversions(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

type Count struct {
    pid64 u64
    port  u16
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    port := u16(pid & 0xffff)
    if Counts.update(pid, Count{pid64: u64(pid), port: port}) != 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsScalarConversionIntegerOverflow(t *testing.T) {
	result := analyzeSource(t, "counts.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    port := u16(70000)
    if port != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1470")
}

func TestAnalyzeRejectsNonIntegerScalarConversions(t *testing.T) {
	result := analyzeSource(t, "flags.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    active := true
    value := u32(active)
    if value != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1463")
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

func TestAnalyzeRejectsBranchLocalOutsideScope(t *testing.T) {
	result := analyzeSource(t, "scope.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() != 0 {
        branch := bpf.current_pid()
    }
    return branch
}
`)
	requireDiagnosticCode(t, result, "HZN1404")
}

func TestAnalyzeRejectsIfInitLocalOutsideScope(t *testing.T) {
	result := analyzeSource(t, "scope.hzn", `package probes

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
    return count.seen
}
`)
	requireDiagnosticCode(t, result, "HZN1404")
}

func TestAnalyzeRejectsForInitLocalOutsideScope(t *testing.T) {
	result := analyzeSource(t, "scope.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    for i := 0; i < 4; i++ {
        bpf.current_pid()
    }
    return i
}
`)
	requireDiagnosticCode(t, result, "HZN1404")
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

func TestAnalyzeIfInitPacketHeaderPasses(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    if tcp := xdp.tcp(ctx); tcp != nil {
        if xdp.ntohs(tcp.dst_port) == 443 {
            return xdp.Drop
        }
    }
    return xdp.Pass
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeAllowsLocalXDPActionReturn(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func Pass(ctx xdp.Context) i32 {
    action := xdp.Pass
    return action
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsRawIntegerXDPReturn(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropAll(ctx xdp.Context) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1448")
}

func TestAnalyzeRejectsRawIntegerAssignedToXDPAction(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropAll(ctx xdp.Context) i32 {
    action := xdp.Pass
    action = 0
    return action
}
`)
	requireDiagnosticCode(t, result, "HZN1448")
}

func TestAnalyzeRejectsXDPActionOutsideXDPReturn(t *testing.T) {
	result := analyzeSource(t, "trace.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return xdp.Drop
}
`)
	requireDiagnosticCode(t, result, "HZN1449")
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

func TestAnalyzeAllowsKernelTimeHelperAcrossProgramKinds(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func Pass(ctx xdp.Context) i32 {
    ts := bpf.ktime_get_ns()
    if ts == 0 {
        return xdp.Pass
    }
    return xdp.Pass
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsKernelTimeHelperArgs(t *testing.T) {
	result := analyzeSource(t, "time.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    bpf.ktime_get_ns(1)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1417")
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

func TestAnalyzeTCProgramPasses(t *testing.T) {
	result := analyzeSource(t, "tc.hzn", `package probes

@capability("kernel.network.tc.drop")
@tc("ingress")
func DropIngress(ctx tc.Context) i32 {
    return tc.Shot
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramTC {
		t.Fatalf("functions = %#v, want one TC function", result.Program.Functions)
	}
	if result.Program.Functions[0].Section.Attach != "ingress" || result.Program.Functions[0].Section.Name != "tc/ingress" {
		t.Fatalf("section = %#v, want tc ingress", result.Program.Functions[0].Section)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Section != "tc/ingress" || manifest.Programs[0].Kind != "tc" {
		t.Fatalf("program manifest = %#v, want tc ingress section", manifest.Programs)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Section != "tc/ingress" || manifest.Capabilities[0].Danger != "drop" {
		t.Fatalf("capability manifest = %#v, want tc drop capability", manifest.Capabilities)
	}
}

func TestAnalyzeRejectsRawIntegerTCReturn(t *testing.T) {
	result := analyzeSource(t, "tc.hzn", `package probes

@tc("ingress")
func PassIngress(ctx tc.Context) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1450")
}

func TestAnalyzeRejectsTCWrongDirection(t *testing.T) {
	result := analyzeSource(t, "tc.hzn", `package probes

@tc("middle")
func PassIngress(ctx tc.Context) i32 {
    return tc.OK
}
`)
	requireDiagnosticCode(t, result, "HZN1313")
}

func TestAnalyzeRejectsTCWrongContext(t *testing.T) {
	result := analyzeSource(t, "tc.hzn", `package probes

@tc("ingress")
func PassIngress(ctx xdp.Context) i32 {
    return tc.OK
}
`)
	requireDiagnosticCode(t, result, "HZN1308")
}

func TestAnalyzeCgroupConnectProgramPasses(t *testing.T) {
	result := analyzeSource(t, "connect.hzn", `package probes

@capability("kernel.network.connect.block")
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
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramCgroup {
		t.Fatalf("functions = %#v, want one cgroup function", result.Program.Functions)
	}
	if result.Program.Functions[0].Section.Attach != "connect4" || result.Program.Functions[0].Section.Name != "cgroup/connect4" {
		t.Fatalf("section = %#v, want cgroup connect4", result.Program.Functions[0].Section)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Section != "cgroup/connect4" || manifest.Programs[0].Kind != "cgroup" {
		t.Fatalf("program manifest = %#v, want cgroup connect4 section", manifest.Programs)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Section != "cgroup/connect4" || manifest.Capabilities[0].Danger != "block" {
		t.Fatalf("capability manifest = %#v, want cgroup block capability", manifest.Capabilities)
	}
	if manifest.Requirements == nil {
		t.Fatal("requirements = nil, want cgroup kernel requirement")
	}
}

func TestAnalyzeRejectsRawIntegerCgroupReturn(t *testing.T) {
	result := analyzeSource(t, "connect.hzn", `package probes

@cgroup("connect4")
func AllowConnect(ctx cgroup.Connect) i32 {
    return 1
}
`)
	requireDiagnosticCode(t, result, "HZN1454")
}

func TestAnalyzeRejectsCgroupWrongAttach(t *testing.T) {
	result := analyzeSource(t, "connect.hzn", `package probes

@cgroup("bind4")
func AllowConnect(ctx cgroup.Connect) i32 {
    return cgroup.Allow
}
`)
	requireDiagnosticCode(t, result, "HZN1315")
}

func TestAnalyzeRejectsCgroupWrongContext(t *testing.T) {
	result := analyzeSource(t, "connect.hzn", `package probes

@cgroup("connect4")
func AllowConnect(ctx xdp.Context) i32 {
    return cgroup.Allow
}
`)
	requireDiagnosticCode(t, result, "HZN1308")
}

func TestAnalyzeRejectsCgroupHelperWrongContext(t *testing.T) {
	result := analyzeSource(t, "connect.hzn", `package probes

@cgroup("connect4")
func AllowConnect(ctx cgroup.Connect) i32 {
    if cgroup.dst_port(1) == 25 {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`)
	requireDiagnosticCode(t, result, "HZN1457")
}

func TestAnalyzeLSMProgramPasses(t *testing.T) {
	result := analyzeSource(t, "lsm.hzn", `package probes

@capability("kernel.file.open.block")
@lsm("file_open")
func DenyFileOpen(ctx lsm.Context) i32 {
    return lsm.Deny
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if len(result.Program.Functions) != 1 || result.Program.Functions[0].Section.Kind != ir.ProgramLSM {
		t.Fatalf("functions = %#v, want one LSM function", result.Program.Functions)
	}
	if result.Program.Functions[0].Section.Attach != "file_open" || result.Program.Functions[0].Section.Name != "lsm/file_open" {
		t.Fatalf("section = %#v, want lsm file_open", result.Program.Functions[0].Section)
	}
	manifest := capability.FromIR(result.Program)
	if len(manifest.Programs) != 1 || manifest.Programs[0].Section != "lsm/file_open" || manifest.Programs[0].Kind != "lsm" {
		t.Fatalf("program manifest = %#v, want lsm file_open section", manifest.Programs)
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Section != "lsm/file_open" || manifest.Capabilities[0].Danger != "block" {
		t.Fatalf("capability manifest = %#v, want lsm block capability", manifest.Capabilities)
	}
}

func TestAnalyzeRejectsRawIntegerLSMReturn(t *testing.T) {
	result := analyzeSource(t, "lsm.hzn", `package probes

@lsm("file_open")
func AllowFileOpen(ctx lsm.Context) i32 {
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1459")
}

func TestAnalyzeRejectsLSMWrongContext(t *testing.T) {
	result := analyzeSource(t, "lsm.hzn", `package probes

@lsm("file_open")
func AllowFileOpen(ctx kprobe.Context) i32 {
    return lsm.Allow
}
`)
	requireDiagnosticCode(t, result, "HZN1308")
}

func TestAnalyzeRejectsEmptyLSMHook(t *testing.T) {
	result := analyzeSource(t, "lsm.hzn", `package probes

@lsm("")
func AllowFileOpen(ctx lsm.Context) i32 {
    return lsm.Allow
}
`)
	requireDiagnosticCode(t, result, "HZN1317")
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

func TestAnalyzeKprobeArgumentHelpersPass(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

type ArgEvent struct {
    dfd i32
    path [256]u8
}

map Events ringbuf[ArgEvent]

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
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsUncheckedProbeReadUserString(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

type ArgEvent struct {
    path [256]u8
}

map Events ringbuf[ArgEvent]

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    bpf.probe_read_user_str(&event.path, kprobe.arg2(ctx))
    Events.submit(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1446")
}

func TestAnalyzeRejectsProbeReadUserStringOutsideKprobe(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

type ArgEvent struct {
    path [256]u8
}

map Events ringbuf[ArgEvent]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    if bpf.probe_read_user_str(&event.path, 0) < 0 {
        Events.discard(event)
        return 0
    }
    Events.submit(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN2300")
}

func TestAnalyzeRejectsProbeReadUserStringBadDestination(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

type ArgEvent struct {
    pid u32
}

map Events ringbuf[ArgEvent]

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := Events.reserve()
    if event == nil {
        return 0
    }
    if bpf.probe_read_user_str(&event.pid, kprobe.arg2(ctx)) < 0 {
        Events.discard(event)
        return 0
    }
    Events.submit(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1474")
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

func TestAnalyzeKretprobeReturnHelperPasses(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    if rc < 0 {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsKprobeHelperWrongContext(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    value := kprobe.arg1(1)
    if value != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1465")
}

func TestAnalyzeRejectsKretprobeHelperWrongContext(t *testing.T) {
	result := analyzeSource(t, "open.hzn", `package probes

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    value := kretprobe.ret(1)
    if value != 0 {
        return 0
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN1467")
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

func TestAnalyzePacketHeaderElseBranchPasses(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp != nil {
        if xdp.ntohs(tcp.dst_port) == 443 {
            return xdp.Drop
        }
    } else {
        return xdp.Pass
    }
    return xdp.Pass
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsPacketHeaderGuardInOnlyOneBranch(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if 1 == 1 {
        if tcp == nil {
            return xdp.Pass
        }
    }
    if xdp.ntohs(tcp.dst_port) == 443 {
        return xdp.Drop
    }
    return xdp.Pass
}
`)
	requireDiagnosticCode(t, result, "HZN2600")
}

func TestAnalyzePacketHeaderGuardedInBothBranchesPasses(t *testing.T) {
	result := analyzeSource(t, "xdp.hzn", `package probes

@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if 1 == 1 {
        if tcp == nil {
            return xdp.Pass
        }
    } else {
        if tcp == nil {
            return xdp.Pass
        }
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
}

func TestAnalyzeRingbufElseBranchConsumesReservation(t *testing.T) {
	result := analyzeSource(t, "else.hzn", `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := Events.reserve()
    if event != nil {
        event.pid = bpf.current_pid()
        Events.submit(event)
    } else {
        return 0
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeIfInitRingbufElseBranchConsumesReservation(t *testing.T) {
	result := analyzeSource(t, "else.hzn", `package probes

type Event struct {
    pid u32
}

map Events ringbuf[Event]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if event := Events.reserve(); event == nil {
        return 0
    } else {
        event.pid = bpf.current_pid()
        Events.submit(event)
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRingbufMutuallyExclusiveConsumeBranchesPass(t *testing.T) {
	result := analyzeSource(t, "branch.hzn", `package probes

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
    if bpf.current_pid() == 0 {
        Events.submit(event)
    } else {
        Events.discard(event)
    }
    return 0
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsConditionalRingbufConsumeWithoutElse(t *testing.T) {
	result := analyzeSource(t, "branch.hzn", `package probes

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
    if bpf.current_pid() == 0 {
        Events.submit(event)
    }
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN2104")
}

func TestAnalyzeRejectsRingbufConsumeAfterMaybeConsumedBranch(t *testing.T) {
	result := analyzeSource(t, "branch.hzn", `package probes

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
    if bpf.current_pid() == 0 {
        Events.submit(event)
    }
    Events.discard(event)
    return 0
}
`)
	requireDiagnosticCode(t, result, "HZN2102")
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
		"probe read before nil check": `package probes

type Event struct {
    path [256]u8
}

map Events ringbuf[Event]

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := Events.reserve()
    if bpf.probe_read_user_str(&event.path, kprobe.arg2(ctx)) < 0 {
        return 0
    }
    if event == nil {
        return 0
    }
    Events.submit(event)
    return 0
}
`,
	}
	want := map[string]string{
		"missing nil check":           "HZN2100",
		"after submit":                "HZN2103",
		"probe read before nil check": "HZN2100",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			result := analyzeSource(t, "array.hzn", source)
			requireDiagnosticCode(t, result, want[name])
		})
	}
}

func TestAnalyzeAllowsExhaustiveBranchReturn(t *testing.T) {
	result := analyzeSource(t, "returns.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() == 0 {
        return 0
    } else {
        return 1
    }
}
`)
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
}

func TestAnalyzeRejectsMissingReturnOnBranchPath(t *testing.T) {
	result := analyzeSource(t, "returns.hzn", `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() == 0 {
        return 0
    }
}
`)
	requireDiagnosticCode(t, result, "HZN1445")
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

func requireDiagnosticCode(t *testing.T, result *Result, code string) diag.Diagnostic {
	t.Helper()
	for _, d := range result.Diagnostics {
		if d.Code == code {
			return d
		}
	}
	t.Fatalf("diagnostics = %#v, want %s", result.Diagnostics, code)
	return diag.Diagnostic{}
}
