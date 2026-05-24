package capability

import (
	"testing"

	"m31labs.dev/horizon/ir"
)

func TestValidateManifest(t *testing.T) {
	m := NewManifest("probes")
	m.Programs = append(m.Programs, Program{Name: "OnExec", Kind: "tracepoint", Attach: "sched:sched_process_exec", Section: "tracepoint/sched:sched_process_exec"})
	m.Capabilities = append(m.Capabilities, Capability{Name: "kernel.process.exec.observe", Kind: "source", Danger: "observe", Program: "OnExec", Section: "tracepoint/sched:sched_process_exec"})
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
		Danger:  "observe",
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
			Name: "Counts",
			Kind: ir.MapKindHash,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "Count"},
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

func TestValidateRejectsMissingTypeSchema(t *testing.T) {
	m := NewManifest("probes")
	m.Programs = append(m.Programs, Program{Name: "OnExec", Kind: "tracepoint", Section: "tracepoint/sched:sched_process_exec"})
	m.Maps = append(m.Maps, Map{Name: "Events", Kind: "ringbuf", Value: "Event"})
	m.Types = append(m.Types, TypeSchema{Name: "OtherEvent", Kind: "struct"})
	m.Capabilities = append(m.Capabilities, Capability{
		Name:    "kernel.process.exec.observe",
		Kind:    "source",
		Danger:  "observe",
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Emits:   "Event",
		Maps:    MapAccess{Events: []string{"Events"}},
	})
	if err := Validate(m); err == nil {
		t.Fatal("Validate succeeded, want missing type schema error")
	}
}
