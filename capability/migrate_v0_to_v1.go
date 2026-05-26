package capability

import (
	"encoding/json"
	"fmt"
)

// v0Manifest mirrors the v0 JSON shape for deserialization.
// The only structural difference from v1 is that Capability.Danger is a
// flat string (e.g. "observe") rather than a DangerAxes object.
// Fields other than Capability.Danger reuse the v1 types (Program, Map,
// TypeSchema, Requirements) because v0 and v1 are byte-compatible for them.
// If any of those v1 types ever diverges, define a v0-specific mirror here.
type v0Manifest struct {
	Schema       string            `json:"schema"`
	Package      string            `json:"package"`
	Programs     []Program         `json:"programs,omitempty"`
	Capabilities []v0Capability    `json:"capabilities"`
	Maps         []Map             `json:"maps,omitempty"`
	Types        []TypeSchema      `json:"types,omitempty"`
	Requirements *Requirements     `json:"requirements,omitempty"`
}

type v0Capability struct {
	Name         string        `json:"name"`
	Kind         string        `json:"kind"`
	Danger       string        `json:"danger"`
	Program      string        `json:"program"`
	Section      string        `json:"section"`
	Emits        string        `json:"emits,omitempty"`
	Maps         MapAccess     `json:"maps"`
	Requirements *Requirements `json:"requirements,omitempty"`
}

// v0DangerTable maps flat v0 danger strings to their canonical v1 axes triples.
// Source: decision memo ~/.hyphae/spaces/m31labs-horizon/decisions/0001-danger-taxonomy-v1.md.
var v0DangerTable = map[string]DangerAxes{
	"observe":    {Mode: "observe", Scope: "event", Reversibility: "none"},
	"mutate":     {Mode: "mutate", Scope: "process", Reversibility: "restart"},
	"drop":       {Mode: "control", Scope: "network", Reversibility: "restart"},
	"block":      {Mode: "control", Scope: "process", Reversibility: "restart"},
	"privileged": {Mode: "mutate", Scope: "system", Reversibility: "persistent"},
}

// migrateV0ToV1 converts a raw v0 manifest JSON into a v1 Manifest.
// It rewrites the flat danger string into a DangerAxes triple using the
// canonical migration table, bumps the schema to SchemaV1, and copies all
// other fields verbatim. Returns an error if any v0 danger value has no
// v1 equivalent or if parsing fails.
func migrateV0ToV1(raw []byte) (Manifest, error) {
	var v0 v0Manifest
	if err := json.Unmarshal(raw, &v0); err != nil {
		return Manifest{}, fmt.Errorf("parse v0 manifest: %w", err)
	}

	if v0.Schema == "" {
		return Manifest{}, fmt.Errorf("v0 manifest schema field is required")
	}
	if v0.Schema != SchemaV0 {
		return Manifest{}, fmt.Errorf("unexpected schema %q for v0→v1 migration", v0.Schema)
	}

	v1 := Manifest{
		Schema:       SchemaV1,
		Package:      v0.Package,
		Programs:     v0.Programs,
		Maps:         v0.Maps,
		Types:        v0.Types,
		Requirements: v0.Requirements,
	}

	for _, c := range v0.Capabilities {
		axes, ok := v0DangerTable[c.Danger]
		if !ok {
			return Manifest{}, fmt.Errorf(
				"capability %q has unknown v0 danger %q — no v1 equivalent exists; update the source manifest",
				c.Name, c.Danger,
			)
		}
		v1.Capabilities = append(v1.Capabilities, Capability{
			Name:         c.Name,
			Kind:         c.Kind,
			Danger:       axes,
			Program:      c.Program,
			Section:      c.Section,
			Emits:        c.Emits,
			Maps:         c.Maps,
			Requirements: c.Requirements,
		})
	}

	if v1.Capabilities == nil {
		v1.Capabilities = []Capability{}
	}

	return v1, nil
}
