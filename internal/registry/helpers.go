// Helper side-effect registry loader. The canonical document lives at
// ~/.hyphae/spaces/m31labs-horizon/specs/helpers-v1.json and is vendored
// byte-identically into this directory as helpers-v1.json.
//
// See spec.horizon-continuum-integration.v1 §A.7 (planned) and
// decision.horizon.0002-helper-side-effects-v1 for the contract role.
//
// This file is a NEW sibling of registry.go (the capability-namespace
// loader). The sibling-file pattern deliberately avoids extending
// registry.go to keep oak's helper-side-effect work and pine's
// verifier-catalog work (roadmap #14) from rebase-colliding on a single
// file. See plans/v0.2-phase-2-oak-helper-side-effects.md §"Cross-track
// coordination" for the binding rationale.

package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed helpers-v1.json
var helpersJSON []byte

// HelpersRegistry is the parsed shape of helpers-v1.json. The Helpers
// slice carries one entry per surface helper Horizon recognizes today.
// Continuum (and any future downstream policy consumer) is expected to
// vendor the same JSON document and parse it into a structurally
// equivalent type.
type HelpersRegistry struct {
	Schema  string   `json:"schema"`
	Version string   `json:"version"`
	Helpers []Helper `json:"helpers"`
}

// Helper is one helper-annotation record. Surface name is keyed against
// the qualified form the Horizon surface language produces
// (e.g. "bpf.current_pid", "ringbuf.reserve"). KernelSymbol records the
// underlying bpf helper kernel symbol — for surface helpers that expand
// to a small wrapper (current_ppid → bpf_get_current_task +
// bpf_probe_read_kernel), only the primary symbol is recorded.
//
// Observes / Mutates use a closed dotted-token vocabulary documented in
// decision.horizon.0002-helper-side-effects-v1. Map / ringbuf identity
// tokens carry the sentinel "$" suffix in the registry; the substitution
// to a concrete map name happens at manifest-emit time
// (capability/from_ir.go).
//
// Requires is BTF-only in v0.2 — kernel-capability bits flow through
// Capability.Requirements.Permissions and are deliberately NOT duplicated
// here.
//
// Resource is one of: reserve | submit | discard | lookup | update |
// delete | "" (empty == not a resource verb).
type Helper struct {
	Name         string   `json:"name"`
	KernelSymbol string   `json:"kernel_symbol"`
	Observes     []string `json:"observes,omitempty"`
	Mutates      []string `json:"mutates,omitempty"`
	Requires     []string `json:"requires,omitempty"`
	Resource     string   `json:"resource,omitempty"`
	Introduced   string   `json:"introduced,omitempty"`
}

// helperResourceTokenPattern matches "map:$", "map:<Ident>",
// "ringbuf:$", or "ringbuf:<Ident>". The "$" placeholder is the
// registry-internal sentinel for "the map / ringbuf identified by the
// call-site receiver"; the emit pipeline substitutes a concrete identifier
// at manifest time.
var helperResourceTokenPattern = regexp.MustCompile(`^(map|ringbuf):(\$|[A-Za-z_][A-Za-z0-9_]*)$`)

// allowedHelperObserveTokens enumerates the closed v0.2 vocabulary for
// observe / mutate fields. Resource tokens (map: / ringbuf:) are
// validated separately via helperResourceTokenPattern. Extending this
// vocabulary is a registry version bump.
var allowedHelperObserveTokens = map[string]bool{
	"task.tgid":             true,
	"task.pid":              true,
	"task.uid":              true,
	"task.gid":              true,
	"task.comm":             true,
	"task.real_parent.tgid": true,
	"kernel.time.monotonic": true,
	"userspace.string":      true,
	"userspace.bytes":       true,
}

// allowedHelperRequiresTokens enumerates the closed v0.2 vocabulary for
// the `requires` field. BTF-only. CONFIG_* / kernel-capability tokens are
// out of scope; the existing Capability.Requirements.Permissions field
// covers the capability surface already.
var allowedHelperRequiresTokens = map[string]bool{
	"task_struct.real_parent": true,
}

// allowedHelperResourceVerbs enumerates the closed verb vocabulary.
// Mirrors capability/requirements.go::mapMethodHelper's switch labels
// one-to-one, plus the explicit "none" sentinel for helpers that hold
// no resource-verb meaning.
var allowedHelperResourceVerbs = map[string]bool{
	"":        true,
	"reserve": true,
	"submit":  true,
	"discard": true,
	"lookup":  true,
	"update":  true,
	"delete":  true,
	"none":    true,
}

// LoadHelpers parses the embedded helpers-v1.json document and validates
// it against the closed vocabularies. Returns a structured error suitable
// for surfacing at process startup.
func LoadHelpers() (HelpersRegistry, error) {
	var r HelpersRegistry
	if err := json.Unmarshal(helpersJSON, &r); err != nil {
		return HelpersRegistry{}, fmt.Errorf("parse helpers registry: %w", err)
	}
	if err := validateHelpersRegistry(r); err != nil {
		return HelpersRegistry{}, err
	}
	return r, nil
}

// MustLoadHelpers parses the embedded helpers-v1.json and panics on
// failure. Failure here would indicate a build-time error in the vendored
// JSON or a vocabulary regression — neither is a runtime concern.
func MustLoadHelpers() HelpersRegistry {
	r, err := LoadHelpers()
	if err != nil {
		panic(fmt.Sprintf("registry: %v", err))
	}
	return r
}

// Helpers is a convenience accessor returning just the helper slice from
// the embedded registry. Equivalent to MustLoadHelpers().Helpers.
func Helpers() []Helper {
	return MustLoadHelpers().Helpers
}

func validateHelpersRegistry(r HelpersRegistry) error {
	if r.Schema != "m31labs.dev/horizon/helpers/v1" {
		return fmt.Errorf("helpers registry schema = %q, want m31labs.dev/horizon/helpers/v1", r.Schema)
	}
	if r.Version != "1" {
		return fmt.Errorf("helpers registry version = %q, want 1", r.Version)
	}
	seen := make(map[string]struct{}, len(r.Helpers))
	for _, h := range r.Helpers {
		if h.Name == "" {
			return fmt.Errorf("helpers registry contains entry with empty name")
		}
		if _, dup := seen[h.Name]; dup {
			return fmt.Errorf("helpers registry contains duplicate name %q", h.Name)
		}
		seen[h.Name] = struct{}{}
		if h.KernelSymbol == "" {
			return fmt.Errorf("helpers registry entry %q has empty kernel_symbol", h.Name)
		}
		if !allowedHelperResourceVerbs[h.Resource] {
			return fmt.Errorf("helpers registry entry %q has illegal resource verb %q", h.Name, h.Resource)
		}
		for _, tok := range h.Observes {
			if err := validateHelperObserveToken(h.Name, "observes", tok); err != nil {
				return err
			}
		}
		for _, tok := range h.Mutates {
			if err := validateHelperObserveToken(h.Name, "mutates", tok); err != nil {
				return err
			}
		}
		for _, tok := range h.Requires {
			if !allowedHelperRequiresTokens[tok] {
				return fmt.Errorf("helpers registry entry %q requires illegal token %q (BTF-only vocabulary in v0.2)", h.Name, tok)
			}
		}
	}
	return nil
}

func validateHelperObserveToken(helperName, field, tok string) error {
	if allowedHelperObserveTokens[tok] {
		return nil
	}
	if helperResourceTokenPattern.MatchString(tok) {
		return nil
	}
	return fmt.Errorf("helpers registry entry %q %s illegal token %q", helperName, field, tok)
}
