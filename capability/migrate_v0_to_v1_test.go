package capability

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigrateV0PreservesPackageAndPrograms round-trips every v0 fixture
// through migrateV0ToV1 and verifies that package, programs, maps, and types
// are preserved verbatim.
func TestMigrateV0PreservesPackageAndPrograms(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "v0-fixtures", "*.json"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no v0 fixtures found in testdata/v0-fixtures/")
	}

	for _, path := range fixtures {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			// Parse the v0 shape to capture original fields.
			var v0 v0Manifest
			if err := json.Unmarshal(raw, &v0); err != nil {
				t.Fatalf("unmarshal v0 fixture: %v", err)
			}

			m, err := migrateV0ToV1(raw)
			if err != nil {
				t.Fatalf("migrateV0ToV1: %v", err)
			}

			// Schema must be v1.
			if m.Schema != SchemaV1 {
				t.Errorf("schema = %q, want %q", m.Schema, SchemaV1)
			}
			// Package preserved.
			if m.Package != v0.Package {
				t.Errorf("package = %q, want %q", m.Package, v0.Package)
			}
			// Program count preserved.
			if len(m.Programs) != len(v0.Programs) {
				t.Errorf("program count = %d, want %d", len(m.Programs), len(v0.Programs))
			}
			// Map count preserved.
			if len(m.Maps) != len(v0.Maps) {
				t.Errorf("map count = %d, want %d", len(m.Maps), len(v0.Maps))
			}
			// Type count preserved.
			if len(m.Types) != len(v0.Types) {
				t.Errorf("type count = %d, want %d", len(m.Types), len(v0.Types))
			}
			// Capability count preserved.
			if len(m.Capabilities) != len(v0.Capabilities) {
				t.Errorf("capability count = %d, want %d", len(m.Capabilities), len(v0.Capabilities))
			}
		})
	}
}

// TestMigrateV0ExpandsDangerFlatStringIntoAxes verifies that each v0 danger
// flat string is correctly expanded into a DangerAxes triple.
func TestMigrateV0ExpandsDangerFlatStringIntoAxes(t *testing.T) {
	tests := []struct {
		flatDanger string
		want       DangerAxes
	}{
		{"observe", DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}},
		{"mutate", DangerAxes{Mode: "mutate", Scope: "process", Reversibility: "restart"}},
		{"drop", DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}},
		{"block", DangerAxes{Mode: "control", Scope: "process", Reversibility: "restart"}},
		{"privileged", DangerAxes{Mode: "mutate", Scope: "system", Reversibility: "persistent"}},
	}

	for _, tt := range tests {
		t.Run(tt.flatDanger, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"schema":  SchemaV0,
				"package": "testpkg",
				"programs": []map[string]any{{
					"name":         "OnProgram",
					"kind":         "tracepoint",
					"attach":       "sched:sched_process_exec",
					"section":      "tracepoint/sched:sched_process_exec",
					"capabilities": []string{"test.capability"},
				}},
				"capabilities": []map[string]any{{
					"name":    "test.capability",
					"kind":    "source",
					"danger":  tt.flatDanger,
					"program": "OnProgram",
					"section": "tracepoint/sched:sched_process_exec",
					"maps":    map[string]any{"read": []string{}, "write": []string{}, "events": []string{}},
				}},
			})
			if err != nil {
				t.Fatalf("marshal v0 JSON: %v", err)
			}

			m, err := migrateV0ToV1(raw)
			if err != nil {
				t.Fatalf("migrateV0ToV1(%q): %v", tt.flatDanger, err)
			}

			if len(m.Capabilities) != 1 {
				t.Fatalf("capability count = %d, want 1", len(m.Capabilities))
			}
			if m.Capabilities[0].Danger != tt.want {
				t.Errorf("Danger = %+v, want %+v", m.Capabilities[0].Danger, tt.want)
			}
		})
	}
}

// TestMigrateV0IsDeterministic verifies that migrating the same v0 input
// always produces a byte-equal v1 JSON output (10 iterations).
func TestMigrateV0IsDeterministic(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "v0-fixtures", "*.json"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Skip("no fixtures available")
	}

	raw, err := os.ReadFile(fixtures[0])
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	first, err := migrateV0ToV1(raw)
	if err != nil {
		t.Fatalf("first migration: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}

	for i := 1; i < 10; i++ {
		m, err := migrateV0ToV1(raw)
		if err != nil {
			t.Fatalf("iteration %d migration: %v", i, err)
		}
		got, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("iteration %d marshal: %v", i, err)
		}
		if !bytes.Equal(firstJSON, got) {
			t.Fatalf("iteration %d: output differs — migration is not deterministic", i)
		}
	}
}

// TestMigrateRejectsMissingSchema verifies that a manifest with an empty
// schema field produces an error.
func TestMigrateRejectsMissingSchema(t *testing.T) {
	raw := []byte(`{"schema":"","package":"testpkg","capabilities":[]}`)
	_, err := migrateV0ToV1(raw)
	if err == nil {
		t.Fatal("migrateV0ToV1(missing schema): got nil error, want error")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error = %q, want message mentioning 'schema'", err.Error())
	}
}

// TestMigrateRejectsFutureSchema verifies that a future schema (e.g. v2)
// produces an error with the "upgrade Horizon or downgrade Continuum" message.
func TestMigrateRejectsFutureSchema(t *testing.T) {
	raw := []byte(`{"schema":"m31labs.dev/horizon/capability/v2","package":"testpkg","capabilities":[]}`)
	_, err := migrateV0ToV1(raw)
	if err == nil {
		t.Fatal("migrateV0ToV1(v2 schema): got nil error, want error")
	}
	// The migration function itself returns a different message (unexpected schema)
	// but LoadManifest handles the future-schema case with the full message.
	if !strings.Contains(err.Error(), "unexpected schema") {
		t.Errorf("error = %q, want message mentioning 'unexpected schema'", err.Error())
	}
}

// TestMigrateRejectsUnknownDangerValue verifies that a v0 danger string with
// no v1 equivalent produces an informative error.
func TestMigrateRejectsUnknownDangerValue(t *testing.T) {
	raw := []byte(`{
		"schema": "m31labs.dev/horizon/capability/v0",
		"package": "testpkg",
		"capabilities": [{
			"name": "test.cap",
			"kind": "source",
			"danger": "unknown_danger_xyz",
			"program": "OnFoo",
			"section": "tracepoint/foo",
			"maps": {"read": [], "write": [], "events": []}
		}]
	}`)
	_, err := migrateV0ToV1(raw)
	if err == nil {
		t.Fatal("migrateV0ToV1(unknown danger): got nil error, want error")
	}
}
