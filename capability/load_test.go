package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

// validV1JSONRaw returns a minimal but valid v1 manifest as JSON bytes.
// Danger is an axes object {"mode": ..., "scope": ..., "reversibility": ...}.
func validV1JSONRaw(t *testing.T) []byte {
	t.Helper()
	// Build a raw JSON map for the v1 shape (danger is an axes object).
	raw := `{
		"schema": "m31labs.dev/horizon/capability/v1",
		"package": "testpkg",
		"programs": [{
			"name": "OnExec",
			"kind": "tracepoint",
			"attach": "sched:sched_process_exec",
			"section": "tracepoint/sched:sched_process_exec",
			"capabilities": ["kernel.process.exec.observe"]
		}],
		"capabilities": [{
			"name": "kernel.process.exec.observe",
			"kind": "source",
			"danger": {"mode": "observe", "scope": "event", "reversibility": "none"},
			"program": "OnExec",
			"section": "tracepoint/sched:sched_process_exec",
			"maps": {"read": [], "write": [], "events": []}
		}]
	}`
	_ = json.RawMessage(raw) // ensure parseable
	return []byte(raw)
}

// validV0JSON returns a minimal but valid v0 manifest as JSON bytes.
func validV0JSON() []byte {
	// Hand-craft the v0 shape: danger is a flat string, schema is v0.
	return []byte(`{
		"schema": "m31labs.dev/horizon/capability/v0",
		"package": "testpkg",
		"programs": [{
			"name": "OnExec",
			"kind": "tracepoint",
			"attach": "sched:sched_process_exec",
			"section": "tracepoint/sched:sched_process_exec",
			"capabilities": ["kernel.process.exec.observe"]
		}],
		"capabilities": [{
			"name": "kernel.process.exec.observe",
			"kind": "source",
			"danger": "observe",
			"program": "OnExec",
			"section": "tracepoint/sched:sched_process_exec",
			"maps": {"read": [], "write": [], "events": []}
		}]
	}`)
}

func TestLoadManifestAcceptsV0AndV1(t *testing.T) {
	t.Run("valid v1 loaded directly", func(t *testing.T) {
		raw := validV1JSONRaw(t)
		m, diags, err := LoadManifest(raw)
		if err != nil {
			t.Fatalf("LoadManifest(v1): %v", err)
		}
		if len(diags) != 0 {
			t.Errorf("LoadManifest(v1) diagnostics = %v, want none", diags)
		}
		if m.Schema != SchemaV1 {
			t.Errorf("schema = %q, want %q", m.Schema, SchemaV1)
		}
		if m.Package != "testpkg" {
			t.Errorf("package = %q, want testpkg", m.Package)
		}
	})

	t.Run("valid v0 migrated to v1 with deprecation warning", func(t *testing.T) {
		raw := validV0JSON()
		m, diags, err := LoadManifest(raw)
		if err != nil {
			t.Fatalf("LoadManifest(v0): %v", err)
		}
		// Must produce the HZN3303 deprecation warning.
		var foundWarn bool
		for _, d := range diags {
			if d.Code == "HZN3303" && d.Severity == diag.SeverityWarning {
				foundWarn = true
			}
		}
		if !foundWarn {
			t.Errorf("LoadManifest(v0) diagnostics = %v, want HZN3303 warning", diags)
		}
		// After migration the schema must be v1.
		if m.Schema != SchemaV1 {
			t.Errorf("migrated schema = %q, want %q", m.Schema, SchemaV1)
		}
		if m.Package != "testpkg" {
			t.Errorf("migrated package = %q, want testpkg", m.Package)
		}
	})

	t.Run("unknown schema produces error", func(t *testing.T) {
		raw := []byte(`{"schema":"m31labs.dev/horizon/capability/v99","package":"x","capabilities":[]}`)
		_, diags, err := LoadManifest(raw)
		if err == nil {
			t.Fatal("LoadManifest(unknown schema): got nil error, want error")
		}
		if !strings.Contains(err.Error(), "unsupported schema") {
			t.Errorf("error = %q, want message containing 'unsupported schema'", err.Error())
		}
		// Must produce the HZN3302 error diagnostic.
		var foundErr bool
		for _, d := range diags {
			if d.Code == "HZN3302" && d.Severity == diag.SeverityError {
				foundErr = true
			}
		}
		if !foundErr {
			t.Errorf("LoadManifest(unknown schema) diagnostics = %v, want HZN3302 error", diags)
		}
	})

	t.Run("missing schema field produces error", func(t *testing.T) {
		raw := []byte(`{"package":"x","capabilities":[]}`)
		_, _, err := LoadManifest(raw)
		if err == nil {
			t.Fatal("LoadManifest(missing schema): got nil error, want error")
		}
	})

	t.Run("future schema produces upgrade message", func(t *testing.T) {
		raw := []byte(`{"schema":"m31labs.dev/horizon/capability/v2","package":"x","capabilities":[]}`)
		_, _, err := LoadManifest(raw)
		if err == nil {
			t.Fatal("LoadManifest(v2 schema): got nil error, want error")
		}
		if !strings.Contains(err.Error(), "upgrade Horizon or downgrade Continuum") {
			t.Errorf("error = %q, want 'upgrade Horizon or downgrade Continuum'", err.Error())
		}
	})
}
