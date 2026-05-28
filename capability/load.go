package capability

import (
	"encoding/json"
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
)

// LoadManifest parses and validates a capability manifest from raw JSON.
//   - v1 manifests are validated and returned directly.
//   - v0 manifests are rejected with an HZN3304 error pointing at the
//     migration guide. The in-memory v0→v1 migration shipped through the
//     v0.2.x deprecation window and was removed in v0.3.
//   - Unknown or missing schemas produce an error.
//
// The returned diagnostics slice may be non-empty even when err is nil
// (rejections are surfaced as error-severity diagnostics). Callers should
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
		errDiag := diag.Diagnostic{
			Code:     "HZN3304",
			Severity: diag.SeverityError,
			Message:  "manifest schema v0 is no longer supported; regenerate the manifest as schema \"m31labs.dev/horizon/capability/v1\"",
			Notes: []string{
				"The in-memory v0→v1 migration shipped through the v0.2.x deprecation window and was removed in v0.3.",
				"See docs/migrations/v0.2-to-v0.3.md for the v0→v1 manifest migration.",
			},
			Suggest: "bump the schema field to \"m31labs.dev/horizon/capability/v1\" and reshape danger to an axes object",
		}
		return Manifest{}, []diag.Diagnostic{errDiag}, nil

	case "":
		errDiag := diag.Diagnostic{
			Code:     "HZN3301",
			Severity: diag.SeverityError,
			Message:  "manifest schema field is required",
		}
		return Manifest{}, []diag.Diagnostic{errDiag}, nil

	default:
		errDiag := diag.Diagnostic{
			Code:     "HZN3302",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("unsupported manifest schema %q — upgrade Horizon or downgrade Continuum", header.Schema),
		}
		return Manifest{}, []diag.Diagnostic{errDiag}, nil
	}
}
