package capability

import (
	"testing"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func TestValidateManifest(t *testing.T) {
	m := NewManifest("probes")
	m.Programs = append(m.Programs, Program{Name: "OnExec", Kind: "tracepoint", Attach: "sched:sched_process_exec", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe"}})
	m.Capabilities = append(m.Capabilities, Capability{Name: "kernel.process.exec.observe", Kind: "source", Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}, Program: "OnExec", Section: "tracepoint/sched:sched_process_exec"})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateAllowsLegacyManifestWithoutTypeSchemas(t *testing.T) {
	m := NewManifest("probes")
	m.Maps = append(m.Maps, Map{Name: "Events", Kind: "ringbuf", Value: "Event"})
	m.Capabilities = append(m.Capabilities, Capability{
		Name:    "kernel.process.exec.observe",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Emits:   "Event",
		Maps:    MapAccess{Events: []string{"Events"}},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestFromIRIncludesTypedEventSchemas(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Structs: []ir.Struct{{
			Name: "ExecEvent",
			Fields: []ir.Field{{
				Name: "pid",
				Type: ir.Type{Name: "u32"},
			}, {
				Name: "comm",
				Type: ir.Type{Len: "16", Elem: &ir.Type{Name: "u8"}},
			}},
		}},
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
		}},
		Maps: []ir.Map{{
			Name: "ExecEvents",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "ExecEvent"},
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.observe",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
			Emits:   "ExecEvent",
			Maps: ir.CapabilityMapAccess{
				Events: []string{"ExecEvents"},
			},
		}},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(m.Types) != 1 {
		t.Fatalf("types = %#v, want one event schema", m.Types)
	}
	typ := m.Types[0]
	if typ.Name != "ExecEvent" || typ.Kind != "struct" || len(typ.Fields) != 2 {
		t.Fatalf("type schema = %#v, want ExecEvent struct with two fields", typ)
	}
	if typ.Size == nil || *typ.Size != 20 {
		t.Fatalf("type size = %#v, want 20", typ.Size)
	}
	if typ.Align == nil || *typ.Align != 4 {
		t.Fatalf("type align = %#v, want 4", typ.Align)
	}
	if typ.Fields[0].Name != "pid" || typ.Fields[0].Type != "u32" {
		t.Fatalf("first field = %#v, want pid u32", typ.Fields[0])
	}
	if typ.Fields[0].Offset == nil || *typ.Fields[0].Offset != 0 {
		t.Fatalf("first field offset = %#v, want 0", typ.Fields[0].Offset)
	}
	if typ.Fields[1].Name != "comm" || typ.Fields[1].Type != "[16]u8" {
		t.Fatalf("second field = %#v, want comm [16]u8", typ.Fields[1])
	}
	if typ.Fields[1].Offset == nil || *typ.Fields[1].Offset != 4 {
		t.Fatalf("second field offset = %#v, want 4", typ.Fields[1].Offset)
	}
	if len(m.Maps) != 1 || m.Maps[0].Value != "ExecEvent" {
		t.Fatalf("maps = %#v, want ExecEvents value ExecEvent", m.Maps)
	}
}

func TestFromIRIncludesMapKeyAndValueTypes(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Structs: []ir.Struct{{
			Name: "Count",
			Fields: []ir.Field{{
				Name: "seen",
				Type: ir.Type{Name: "u64"},
			}},
		}},
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
		}},
		Maps: []ir.Map{{
			Name:       "Counts",
			Kind:       ir.MapKindHash,
			Key:        ir.Type{Name: "u32"},
			Val:        ir.Type{Name: "Count"},
			MaxEntries: "4096",
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.count",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
			Maps: ir.CapabilityMapAccess{
				Read:  []string{"Counts"},
				Write: []string{"Counts"},
			},
		}},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(m.Maps) != 1 || m.Maps[0].Key != "u32" || m.Maps[0].Value != "Count" {
		t.Fatalf("maps = %#v, want Counts hash[u32, Count]", m.Maps)
	}
	if m.Maps[0].MaxEntries != "4096" {
		t.Fatalf("max_entries = %q, want 4096", m.Maps[0].MaxEntries)
	}
}

func TestFromIRIncludesKernelRequirements(t *testing.T) {
	m := FromIR(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnExec",
			Section: ir.Section{
				Kind:   ir.ProgramTracepoint,
				Name:   "tracepoint/sched/sched_process_exec",
				Attach: "sched:sched_process_exec",
			},
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "short_var",
					Name: "event",
					Value: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "Events"}, Field: "reserve"},
					},
				}, {
					Kind: "assign",
					Value: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "bpf"}, Field: "current_pid"},
					},
				}, {
					Kind: "assign",
					Value: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "bpf"}, Field: "ktime_get_ns"},
					},
				}, {
					Kind: "assign",
					Value: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "bpf"}, Field: "current_ppid"},
					},
				}, {
					Kind: "expr",
					Expr: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "bpf"}, Field: "probe_read_user_str"},
					},
				}, {
					Kind: "expr",
					Expr: &ir.Expr{
						Kind: "call",
						Func: &ir.Expr{Kind: "selector", Operand: &ir.Expr{Kind: "ident", Name: "Events"}, Field: "submit"},
						Args: []ir.Expr{{Kind: "ident", Name: "event"}},
					},
				}},
			}},
		}},
		Maps: []ir.Map{{
			Name: "Events",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "Event"},
		}, {
			Name: "RecentByCPU",
			Kind: ir.MapKindLRUPerCPU,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "u64"},
		}},
		Capabilities: []ir.Capability{{
			Name:    "kernel.process.exec.observe",
			Kind:    ir.CapabilitySource,
			Danger:  ir.DangerObserve,
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
			Maps: ir.CapabilityMapAccess{
				Events: []string{"Events"},
			},
		}},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if m.Requirements == nil {
		t.Fatal("requirements = nil, want kernel requirements")
	}
	if m.Requirements.MinKernel != "5.8" {
		t.Fatalf("min_kernel = %q, want 5.8", m.Requirements.MinKernel)
	}
	requireFeature(t, m.Requirements.Programs, "tracepoint", "4.7")
	requireFeature(t, m.Requirements.Maps, "ringbuf", "5.8")
	requireFeature(t, m.Requirements.Maps, "lru_percpu_hash", "4.10")
	requireFeature(t, m.Requirements.Helpers, "bpf_get_current_pid_tgid", "4.1")
	requireFeature(t, m.Requirements.Helpers, "bpf_get_current_task", "4.8")
	requireFeature(t, m.Requirements.Helpers, "bpf_probe_read_kernel", "5.5")
	requireFeature(t, m.Requirements.Helpers, "bpf_probe_read_user_str", "5.5")
	requireFeature(t, m.Requirements.Helpers, "bpf_ktime_get_ns", "4.1")
	requireFeature(t, m.Requirements.Helpers, "bpf_ringbuf_reserve", "5.8")
	requireFeature(t, m.Requirements.Helpers, "bpf_ringbuf_submit", "5.8")
	requireString(t, m.Requirements.Permissions, "bpf_program_load")
	requireString(t, m.Requirements.Permissions, "perf_event_open")
	requireString(t, m.Requirements.Features, "tracefs")

	if len(m.Capabilities) != 1 || m.Capabilities[0].Requirements == nil {
		t.Fatalf("capabilities = %#v, want per-capability requirements", m.Capabilities)
	}
	capReqs := m.Capabilities[0].Requirements
	if capReqs.MinKernel != "5.8" {
		t.Fatalf("capability min_kernel = %q, want 5.8", capReqs.MinKernel)
	}
	requireFeature(t, capReqs.Programs, "tracepoint", "4.7")
	requireFeature(t, capReqs.Maps, "ringbuf", "5.8")
	rejectFeature(t, capReqs.Maps, "lru_percpu_hash")
	requireFeature(t, capReqs.Helpers, "bpf_probe_read_user_str", "5.5")
	requireFeature(t, capReqs.Helpers, "bpf_ringbuf_submit", "5.8")
	requireString(t, capReqs.Permissions, "bpf_program_load")
	requireString(t, capReqs.Permissions, "perf_event_open")
	requireString(t, capReqs.Features, "tracefs")
}

func requireFeature(t *testing.T, items []FeatureRequirement, name string, minKernel string) {
	t.Helper()
	for _, item := range items {
		if item.Name == name {
			if item.MinKernel != minKernel {
				t.Fatalf("%s min_kernel = %q, want %q", name, item.MinKernel, minKernel)
			}
			return
		}
	}
	t.Fatalf("requirements missing %s in %#v", name, items)
}

func rejectFeature(t *testing.T, items []FeatureRequirement, name string) {
	t.Helper()
	for _, item := range items {
		if item.Name == name {
			t.Fatalf("requirements include unexpected %s in %#v", name, items)
		}
	}
}

func requireString(t *testing.T, items []string, want string) {
	t.Helper()
	for _, item := range items {
		if item == want {
			return
		}
	}
	t.Fatalf("requirements missing %q in %#v", want, items)
}

func TestFromIRIncludesProgramRuntimeRequirements(t *testing.T) {
	tests := []struct {
		name        string
		kind        ir.ProgramKind
		permissions []string
		features    []string
	}{
		{
			name:        "tracepoint",
			kind:        ir.ProgramTracepoint,
			permissions: []string{"bpf_program_load", "perf_event_open"},
			features:    []string{"tracefs"},
		},
		{
			name:        "kprobe",
			kind:        ir.ProgramKprobe,
			permissions: []string{"bpf_program_load", "perf_event_open"},
			features:    []string{"kprobes", "tracefs"},
		},
		{
			name:        "kretprobe",
			kind:        ir.ProgramKretprobe,
			permissions: []string{"bpf_program_load", "perf_event_open"},
			features:    []string{"kprobes", "tracefs"},
		},
		{
			name:        "xdp",
			kind:        ir.ProgramXDP,
			permissions: []string{"bpf_program_load", "net_admin"},
			features:    []string{"netdev_xdp"},
		},
		{
			name:        "tc",
			kind:        ir.ProgramTC,
			permissions: []string{"bpf_program_load", "net_admin"},
			features:    []string{"tc_clsact"},
		},
		{
			name:        "cgroup",
			kind:        ir.ProgramCgroup,
			permissions: []string{"bpf_program_load", "cgroup_admin"},
			features:    []string{"cgroup_v2"},
		},
		{
			name:        "lsm",
			kind:        ir.ProgramLSM,
			permissions: []string{"bpf_program_load", "lsm_admin"},
			features:    []string{"bpf_lsm"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := FromIR(ir.Program{
				Package: "probes",
				Functions: []ir.Function{{
					Name:    "Program",
					Section: ir.Section{Kind: tt.kind, Attach: "attach"},
				}},
				Capabilities: []ir.Capability{{
					Name:    "test.runtime.requirement.observe",
					Kind:    ir.CapabilitySource,
					Danger:  ir.DangerObserve,
					Program: "Program",
					Section: string(tt.kind),
				}},
			})
			if err := Validate(m); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if m.Requirements == nil {
				t.Fatal("requirements = nil, want runtime requirements")
			}
			for _, permission := range tt.permissions {
				requireString(t, m.Requirements.Permissions, permission)
			}
			for _, feature := range tt.features {
				requireString(t, m.Requirements.Features, feature)
			}
		})
	}
}

func TestValidateRejectsInvalidTypeLayoutMetadata(t *testing.T) {
	negativeSize := -1
	zeroAlign := 0
	negativeOffset := -1
	tooLargeOffset := 12
	tests := map[string]Manifest{
		"negative size": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Types:        []TypeSchema{{Name: "Event", Kind: "struct", Size: &negativeSize}},
		},
		"zero align": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Types:        []TypeSchema{{Name: "Event", Kind: "struct", Align: &zeroAlign}},
		},
		"negative offset": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Types: []TypeSchema{{
				Name:   "Event",
				Kind:   "struct",
				Fields: []FieldSchema{{Name: "pid", Type: "u32", Offset: &negativeOffset}},
			}},
		},
		"offset exceeds size": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Types: []TypeSchema{{
				Name:   "Event",
				Kind:   "struct",
				Size:   intPtr(8),
				Fields: []FieldSchema{{Name: "pid", Type: "u32", Offset: &tooLargeOffset}},
			}},
		},
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Validate(manifest); err == nil {
				t.Fatal("Validate succeeded, want layout metadata error")
			}
		})
	}
}

func TestValidateRejectsDuplicateManifestIdentities(t *testing.T) {
	tests := map[string]Manifest{
		"program": {
			Schema:  SchemaV0,
			Package: "probes",
			Programs: []Program{
				{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec"},
				{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec"},
			},
			Capabilities: []Capability{},
		},
		"map": {
			Schema:  SchemaV0,
			Package: "probes",
			Maps: []Map{
				{Name: "Events", Kind: "ringbuf", Value: "Event"},
				{Name: "Events", Kind: "ringbuf", Value: "Event"},
			},
			Capabilities: []Capability{},
		},
		"type": {
			Schema:  SchemaV0,
			Package: "probes",
			Types: []TypeSchema{
				{Name: "Event", Kind: "struct"},
				{Name: "Event", Kind: "struct"},
			},
			Capabilities: []Capability{},
		},
		"type field": {
			Schema:       SchemaV0,
			Package:      "probes",
			Types:        []TypeSchema{{Name: "Event", Kind: "struct", Fields: []FieldSchema{{Name: "pid", Type: "u32"}, {Name: "pid", Type: "u32"}}}},
			Capabilities: []Capability{},
		},
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Validate(manifest); err == nil {
				t.Fatal("Validate succeeded, want duplicate identity error")
			}
		})
	}
}

func TestValidateRejectsUnsupportedEnumValues(t *testing.T) {
	tests := map[string]Manifest{
		"program kind": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "definitely_not_a_program_kind_xyz", Section: "sockops"}},
			Capabilities: []Capability{},
		},
		"map kind": {
			Schema:       SchemaV0,
			Package:      "probes",
			Maps:         []Map{{Name: "Events", Kind: "queue", Value: "u32"}},
			Capabilities: []Capability{},
		},
		"map max entries": {
			Schema:       SchemaV0,
			Package:      "probes",
			Maps:         []Map{{Name: "Events", Kind: "ringbuf", Value: "u32", MaxEntries: "0"}},
			Capabilities: []Capability{},
		},
		"ringbuf max entries": {
			Schema:       SchemaV0,
			Package:      "probes",
			Maps:         []Map{{Name: "Events", Kind: "ringbuf", Value: "u32", MaxEntries: "3000"}},
			Capabilities: []Capability{},
		},
		"type kind": {
			Schema:       SchemaV0,
			Package:      "probes",
			Types:        []TypeSchema{{Name: "Event", Kind: "union"}},
			Capabilities: []Capability{},
		},
		"capability kind": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{{Name: "kernel.process.exec.observe", Kind: "sink", Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}, Program: "OnExec", Section: "tracepoint/sched/sched_process_exec"}},
		},
		"danger": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{{Name: "kernel.process.exec.observe", Kind: "source", Danger: DangerAxes{Mode: "destroy", Scope: "event", Reversibility: "none"}, Program: "OnExec", Section: "tracepoint/sched/sched_process_exec"}},
		},
		"capability namespace": {
			Schema:   SchemaV0,
			Package:  "probes",
			Programs: []Program{{Name: "Drop", Kind: "xdp", Section: "xdp"}},
			Capabilities: []Capability{{
				Name:    "kernel.process.exec.observe",
				Kind:    "source",
				Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
				Program: "Drop",
				Section: "xdp",
			}},
		},
		"unknown helper requirement": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				MinKernel: "5.8",
				Helpers:   []FeatureRequirement{{Name: "bpf_unknown", MinKernel: "5.8"}},
			},
		},
		"invalid requirement version": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				MinKernel: "5.x",
				Maps:      []FeatureRequirement{{Name: "ringbuf", MinKernel: "5.8"}},
			},
		},
		"aggregate lower than feature": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				MinKernel: "4.1",
				Maps:      []FeatureRequirement{{Name: "ringbuf", MinKernel: "5.8"}},
			},
		},
		"unknown permission requirement": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				Permissions: []string{"root"},
			},
		},
		"duplicate permission requirement": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				Permissions: []string{"bpf_program_load", "bpf_program_load"},
			},
		},
		"unknown feature requirement": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				Features: []string{"debugfs"},
			},
		},
		"duplicate feature requirement": {
			Schema:       SchemaV0,
			Package:      "probes",
			Capabilities: []Capability{},
			Requirements: &Requirements{
				Features: []string{"tracefs", "tracefs"},
			},
		},
		"capability requirement": {
			Schema:  SchemaV0,
			Package: "probes",
			Capabilities: []Capability{{
				Name:    "kernel.process.exec.observe",
				Kind:    "source",
				Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
				Program: "OnExec",
				Section: "tracepoint/sched/sched_process_exec",
				Requirements: &Requirements{
					MinKernel: "5.8",
					Helpers:   []FeatureRequirement{{Name: "bpf_unknown", MinKernel: "5.8"}},
				},
			}},
		},
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			err := Validate(manifest)
			if err == nil {
				t.Fatal("Validate succeeded, want enum validation error")
			}
			d, ok := DiagnosticForError(err)
			if !ok {
				t.Fatalf("DiagnosticForError(%T) = false", err)
			}
			if d.Code != "HZN3300" || d.Severity != diag.SeverityError {
				t.Fatalf("diagnostic = %#v, want HZN3300 error", d)
			}
		})
	}
}

func TestValidateRejectsProgramCapabilityIndexMismatches(t *testing.T) {
	execCap := Capability{Name: "kernel.process.exec.observe", Kind: "source", Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}, Program: "OnExec", Section: "tracepoint/sched:sched_process_exec"}
	countCap := Capability{Name: "kernel.process.exec.count", Kind: "source", Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}, Program: "OnExec", Section: "tracepoint/sched:sched_process_exec"}
	dropCap := Capability{Name: "kernel.network.xdp.drop", Kind: "source", Danger: DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}, Program: "Drop", Section: "xdp"}
	tests := map[string]Manifest{
		"missing program capability list": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec"}},
			Capabilities: []Capability{execCap},
		},
		"unknown listed capability": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe"}}},
			Capabilities: []Capability{},
		},
		"duplicate listed capability": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe", "kernel.process.exec.observe"}}},
			Capabilities: []Capability{execCap},
		},
		"wrong owner": {
			Schema:  SchemaV0,
			Package: "probes",
			Programs: []Program{
				{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.network.xdp.drop"}},
				{Name: "Drop", Kind: "xdp", Section: "xdp", Capabilities: []string{"kernel.network.xdp.drop"}},
			},
			Capabilities: []Capability{dropCap},
		},
		"top-level capability missing from program list": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe"}}},
			Capabilities: []Capability{execCap, countCap},
		},
		"duplicate top-level capability": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe"}}},
			Capabilities: []Capability{execCap, execCap},
		},
		"empty listed capability": {
			Schema:       SchemaV0,
			Package:      "probes",
			Programs:     []Program{{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{""}}},
			Capabilities: []Capability{execCap},
		},
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Validate(manifest); err == nil {
				t.Fatal("Validate succeeded, want program capability index error")
			}
		})
	}
}

func TestValidateAllowsPerCPUAndLRUMapKinds(t *testing.T) {
	m := NewManifest("probes")
	m.Programs = append(m.Programs, Program{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.count"}})
	m.Maps = append(m.Maps,
		Map{Name: "Counts", Kind: "percpu_hash", Key: "u32", Value: "u64", MaxEntries: "128"},
		Map{Name: "Slots", Kind: "percpu_array", Key: "u32", Value: "u64"},
		Map{Name: "Recent", Kind: "lru_hash", Key: "u32", Value: "u64", MaxEntries: "64"},
		Map{Name: "RecentByCPU", Kind: "lru_percpu_hash", Key: "u32", Value: "u64", MaxEntries: "64"},
	)
	m.Capabilities = append(m.Capabilities, Capability{
		Name:    "kernel.process.exec.count",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Maps:    MapAccess{Read: []string{"Counts", "Recent"}, Write: []string{"Counts", "Slots", "Recent", "RecentByCPU"}},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsMissingTypeSchema(t *testing.T) {
	m := NewManifest("probes")
	m.Programs = append(m.Programs, Program{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec", Capabilities: []string{"kernel.process.exec.observe"}})
	m.Maps = append(m.Maps, Map{Name: "Events", Kind: "ringbuf", Value: "Event"})
	m.Types = append(m.Types, TypeSchema{Name: "OtherEvent", Kind: "struct"})
	m.Capabilities = append(m.Capabilities, Capability{
		Name:    "kernel.process.exec.observe",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Emits:   "Event",
		Maps:    MapAccess{Events: []string{"Events"}},
	})
	if err := Validate(m); err == nil {
		t.Fatal("Validate succeeded, want missing type schema error")
	}
}
