// Package registry loads the canonical capability-namespace registry
// vendored from the Hyphae spec at
// ~/.hyphae/spaces/m31labs-horizon/specs/capability-namespaces-v1.json.
// See spec.horizon-continuum-integration.v1 §A.3.
package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed capability-namespaces-v1.json
var registryJSON []byte

type Registry struct {
	Schema     string      `json:"schema"`
	Version    string      `json:"version"`
	Namespaces []Namespace `json:"namespaces"`
}

type Namespace struct {
	Namespace           string   `json:"namespace"`
	AttachSurface       string   `json:"attach_surface"`
	AttachStrings       []string `json:"attach_strings"`
	AllowedDangerLeaves []string `json:"allowed_danger_leaves"`
	Introduced          string   `json:"introduced"`
}

// MustLoad parses the embedded registry JSON. Panics if the embedded
// document is malformed — that would indicate a build-time error in
// the vendored file, not a runtime concern.
func MustLoad() Registry {
	r, err := Load()
	if err != nil {
		panic(fmt.Sprintf("registry: %v", err))
	}
	return r
}

// Load parses the embedded registry JSON and returns the registry.
func Load() (Registry, error) {
	var r Registry
	if err := json.Unmarshal(registryJSON, &r); err != nil {
		return Registry{}, fmt.Errorf("parse capability namespaces registry: %w", err)
	}
	return r, nil
}
