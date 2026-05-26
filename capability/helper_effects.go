// Package-level helper-side-effect surface for the v1 manifest.
//
// This file is the capability-side reader of the helper-side-effect
// registry vendored at internal/registry/helpers-v1.json.
//
// Subtask 2a (this commit): typed lookup. LookupHelperEffects(name) is
// the PUBLIC, single-helper accessor backed by the embedded registry.
// It is the integration handle downstream consumers (notably maple's
// helper-effect summary lattice for roadmap #13) will call into; do
// not rename or restrict its signature without cross-track sign-off.
//
// The registry stores "map:$" / "ringbuf:$" as sentinel placeholders
// for map / ringbuf method helpers. LookupHelperEffects preserves
// those placeholders verbatim — substitution to a concrete receiver
// name happens at manifest-emit time (Subtask 2b, on a COPY of the
// template returned here). The accessor hands back fresh copies of
// every slice field so callers may mutate the result without
// poisoning the registry singleton.
//
// No HZN-coded diagnostics emit from this file. Registry-shape
// validation lives in internal/registry/helpers.go; manifest-shape
// validation lives in capability/validate.go (added by Task 4).

package capability

import (
	"m31labs.dev/horizon/internal/registry"
)

// HelperEffectTemplate is the registry's view of a single helper —
// observes / mutates strings may still contain the "$" placeholder if
// the helper is a map / ringbuf method. The Task 2b walker substitutes
// those placeholders with concrete receiver names when projecting the
// template into a manifest-emitted HelperEffect.
type HelperEffectTemplate struct {
	Name     string
	Observes []string
	Mutates  []string
	Requires []string
	Resource string
}

// helperTemplates is the package-level cache of registry entries keyed
// by surface name. Loaded once via registry.MustLoadHelpers() — a
// failure here means the vendored JSON is structurally broken, which
// is a build-time error, not a runtime concern.
var helperTemplates = loadHelperTemplates()

func loadHelperTemplates() map[string]HelperEffectTemplate {
	r := registry.MustLoadHelpers()
	out := make(map[string]HelperEffectTemplate, len(r.Helpers))
	for _, h := range r.Helpers {
		out[h.Name] = HelperEffectTemplate{
			Name:     h.Name,
			Observes: append([]string(nil), h.Observes...),
			Mutates:  append([]string(nil), h.Mutates...),
			Requires: append([]string(nil), h.Requires...),
			Resource: h.Resource,
		}
	}
	return out
}

// LookupHelperEffects returns the registry template for a surface
// helper name (e.g. "bpf.current_pid", "ringbuf.reserve"). The
// returned template's slice fields are fresh copies — callers may
// mutate them without poisoning the registry. ok is false when the
// name is unknown.
//
// This is the PUBLIC accessor downstream consumers integrate against.
// In particular, maple's helper-effect summary lattice (roadmap #13)
// calls into this surface; do not rename or restrict its signature
// without cross-track sign-off.
func LookupHelperEffects(name string) (HelperEffectTemplate, bool) {
	tmpl, ok := helperTemplates[name]
	if !ok {
		return HelperEffectTemplate{}, false
	}
	return HelperEffectTemplate{
		Name:     tmpl.Name,
		Observes: append([]string(nil), tmpl.Observes...),
		Mutates:  append([]string(nil), tmpl.Mutates...),
		Requires: append([]string(nil), tmpl.Requires...),
		Resource: tmpl.Resource,
	}, true
}
