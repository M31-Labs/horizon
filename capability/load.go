package capability

import (
	"encoding/json"
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
)

// LoadManifest parses and validates a capability manifest from raw JSON.
// It accepts both v0 and v1 schema manifests:
//   - v1 manifests are validated and returned directly.
//   - v0 manifests are migrated to v1 in memory and returned with a
//     HZN3303 deprecation warning. v0 support will be removed in v0.3.
//   - Unknown schemas produce an error.
//
// The returned diagnostics slice may be non-empty even on success (e.g.,
// a deprecation warning when loading a v0 manifest). Callers should
// inspect diagnostics regardless of whether err is nil.
func LoadManifest(raw []byte) (Manifest, []diag.Diagnostic, error) {
	// Peek the schema field without full unmarshalling.
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Manifest{}, nil, fmt.Errorf("capability manifest: failed to parse schema field: %w", err)
	}

	switch header.Schema {
	case SchemaV1:
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return Manifest{}, nil, fmt.Errorf("capability manifest: failed to parse v1 manifest: %w", err)
		}
		if err := Validate(m); err != nil {
			return Manifest{}, nil, err
		}
		return m, nil, nil

	case SchemaV0:
		m, err := migrateV0ToV1(raw)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("capability manifest: v0 migration failed: %w", err)
		}
		if err := Validate(m); err != nil {
			return Manifest{}, nil, err
		}
		warn := diag.Diagnostic{
			Code:     "HZN3303",
			Severity: diag.SeverityWarning,
			Message:  "manifest schema v0 is deprecated; will be removed in v0.3",
			Notes: []string{
				"Call capability.LoadManifest() to load v0 manifests — they are migrated to v1 in memory.",
				"Update manifests to emit schema \"m31labs.dev/horizon/capability/v1\" to suppress this warning.",
			},
			Suggest: "bump the schema field to \"m31labs.dev/horizon/capability/v1\" and reshape danger to an axes object",
		}
		return m, []diag.Diagnostic{warn}, nil

	case "":
		return Manifest{}, nil, fmt.Errorf("capability manifest: schema field is required")

	default:
		return Manifest{}, nil, fmt.Errorf(
			"capability manifest: unsupported schema %q — upgrade Horizon or downgrade Continuum",
			header.Schema,
		)
	}
}
