// Package-level helper-side-effect surface for the v1 manifest.
//
// This file is the capability-side reader of the helper-side-effect
// registry vendored at internal/registry/helpers-v1.json.
//
// Two surfaces live here:
//
//   - LookupHelperEffects(name) — PUBLIC single-helper accessor backed
//     by the embedded registry. It is the integration handle downstream
//     consumers (notably maple's helper-effect summary lattice for
//     roadmap #13) will call into; do not rename or restrict its
//     signature without cross-track sign-off.
//   - ComputeHelperEffectsForFunction(program, fn) — per-program
//     aggregation walker. Reuses capability.reachableFunctions from
//     requirements.go to traverse user-defined functions, harvests
//     annotated helper calls, substitutes map / ringbuf placeholders
//     with concrete receiver names, dedupes by Name, sorts by Name.
//
// The registry stores "map:$" / "ringbuf:$" as sentinel placeholders
// for map / ringbuf method helpers. LookupHelperEffects preserves
// those placeholders verbatim; ComputeHelperEffectsForFunction
// substitutes them on a COPY of the template, leaving the underlying
// registry entries immutable. The accessor hands back fresh copies of
// every slice field so callers may mutate the result without
// poisoning the registry singleton.
//
// No HZN-coded diagnostics emit from this file. Registry-shape
// validation lives in internal/registry/helpers.go; manifest-shape
// validation lives in capability/validate.go (added by Task 4).

package capability

import (
	"sort"
	"strings"

	"m31labs.dev/horizon/internal/registry"
	"m31labs.dev/horizon/ir"
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

// HelperEffect is the manifest-emitted view of a helper-side-effect
// annotation: registry-template fields with all "map:$" / "ringbuf:$"
// placeholders already resolved to concrete map / ringbuf names.
//
// Task 3a will add the matching `Capability.HelperEffects []HelperEffect`
// field on `capability.Manifest`; the type is introduced here because
// the walker output is keyed against it. Defining it next to the
// producer avoids back-edges from manifest.go into the helper-effects
// machinery.
type HelperEffect struct {
	Name     string   `json:"name"`
	Observes []string `json:"observes,omitempty"`
	Mutates  []string `json:"mutates,omitempty"`
	Requires []string `json:"requires,omitempty"`
	Resource string   `json:"resource,omitempty"`
}

// ComputeHelperEffectsForFunction walks every function reachable from
// fn (using the same recursion the requirements walker uses) and
// returns the union of annotated helper effects, sorted by Name and
// deduplicated.
//
// Map / ringbuf method calls (e.g. OpenEvents.reserve(...)) have their
// "map:$" / "ringbuf:$" placeholders substituted with the concrete
// receiver name on a copy of the template. The registry template
// itself is never mutated.
//
// Returns nil — not an empty slice — when no annotated helpers are
// reachable, so that the json `omitempty` tag on
// Capability.HelperEffects (added by Task 3a) elides the field cleanly.
func ComputeHelperEffectsForFunction(program ir.Program, fn ir.Function) []HelperEffect {
	functions := functionsByName(program.Functions)
	collector := newHelperEffectCollector()
	for _, reachable := range reachableFunctions(fn, functions) {
		for _, block := range reachable.Body {
			for _, stmt := range block.Statements {
				collector.walkStatement(stmt)
			}
		}
	}
	return collector.build()
}

// helperEffectCollector accumulates HelperEffect entries keyed by Name
// during an IR walk. The first observation of a helper wins — repeat
// observations of the same surface name are dropped, preserving the
// dedup contract from §D-6 of the plan. The walker recursively
// descends every expression in every statement, mirroring the shape
// of the requirements walker's traversal (see requirements.go) so the
// two walkers stay in lockstep over future IR shape changes.
type helperEffectCollector struct {
	byName map[string]HelperEffect
}

func newHelperEffectCollector() *helperEffectCollector {
	return &helperEffectCollector{byName: map[string]HelperEffect{}}
}

func (c *helperEffectCollector) record(eff HelperEffect) {
	if eff.Name == "" {
		return
	}
	if _, ok := c.byName[eff.Name]; ok {
		return
	}
	c.byName[eff.Name] = eff
}

func (c *helperEffectCollector) build() []HelperEffect {
	if len(c.byName) == 0 {
		return nil
	}
	names := make([]string, 0, len(c.byName))
	for name := range c.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]HelperEffect, 0, len(names))
	for _, name := range names {
		out = append(out, c.byName[name])
	}
	return out
}

func (c *helperEffectCollector) walkStatement(stmt ir.Statement) {
	c.walkExpr(stmt.Target)
	c.walkExpr(stmt.Value)
	c.walkExpr(stmt.Expr)
	c.walkExpr(stmt.Cond)
	if stmt.Init != nil {
		c.walkStatement(*stmt.Init)
	}
	if stmt.Post != nil {
		c.walkStatement(*stmt.Post)
	}
	for _, child := range stmt.Then {
		c.walkStatement(child)
	}
	for _, child := range stmt.Else {
		c.walkStatement(child)
	}
	for _, child := range stmt.Body {
		c.walkStatement(child)
	}
	for _, kase := range stmt.Cases {
		for i := range kase.Values {
			c.walkExpr(&kase.Values[i])
		}
		for _, child := range kase.Body {
			c.walkStatement(child)
		}
	}
}

func (c *helperEffectCollector) walkExpr(expr *ir.Expr) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		c.observeCall(expr)
	}
	c.walkExpr(expr.Operand)
	c.walkExpr(expr.Left)
	c.walkExpr(expr.Right)
	c.walkExpr(expr.Func)
	for i := range expr.Args {
		c.walkExpr(&expr.Args[i])
	}
	for i := range expr.Fields {
		c.walkExpr(&expr.Fields[i].Value)
	}
}

func (c *helperEffectCollector) observeCall(expr *ir.Expr) {
	// Free-standing intrinsic, e.g. bpf.current_pid(...) — qualified
	// name resolves directly against the registry.
	if name := qualifiedName(expr.Func); name != "" {
		if tmpl, ok := LookupHelperEffects(name); ok {
			c.record(materializeHelperEffect(tmpl, ""))
		}
	}
	// Map / ringbuf method call, e.g. OpenEvents.reserve(...). The
	// receiver becomes the substitution target for any "$" placeholder
	// in the template's observe / mutate tokens.
	if receiver, method, ok := mapMethodCall(expr); ok {
		surface := mapMethodSurfaceName(method)
		if surface == "" {
			return
		}
		if tmpl, ok := LookupHelperEffects(surface); ok {
			c.record(materializeHelperEffect(tmpl, receiver))
		}
	}
}

// mapMethodSurfaceName maps the raw method label coming off
// mapMethodCall (e.g. "reserve", "lookup") to the qualified surface
// name the registry keys against. Mirrors the case labels in
// capability/requirements.go::mapMethodHelper one-to-one but lifts the
// answer to surface-name space — the registry deals in qualified
// names (map.lookup, ringbuf.reserve), not bare verbs.
func mapMethodSurfaceName(method string) string {
	switch method {
	case "lookup":
		return "map.lookup"
	case "update":
		return "map.update"
	case "delete":
		return "map.delete"
	case "reserve":
		return "ringbuf.reserve"
	case "submit":
		return "ringbuf.submit"
	case "discard":
		return "ringbuf.discard"
	default:
		return ""
	}
}

// materializeHelperEffect projects a registry template into the
// manifest-emitted HelperEffect shape. If mapName is non-empty, any
// "$" sentinel in an observe / mutate token is replaced with the
// concrete name; otherwise template tokens pass through unchanged.
//
// Substitution operates on a COPY of the template — LookupHelperEffects
// already hands back independent slices, so this rewrite is safe
// regardless. The registry singleton remains immutable.
func materializeHelperEffect(tmpl HelperEffectTemplate, mapName string) HelperEffect {
	return HelperEffect{
		Name:     tmpl.Name,
		Observes: substitutePlaceholders(tmpl.Observes, mapName),
		Mutates:  substitutePlaceholders(tmpl.Mutates, mapName),
		Requires: append([]string(nil), tmpl.Requires...),
		Resource: tmpl.Resource,
	}
}

func substitutePlaceholders(tokens []string, mapName string) []string {
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		out = append(out, substitutePlaceholder(tok, mapName))
	}
	return out
}

func substitutePlaceholder(token string, mapName string) string {
	if mapName == "" {
		return token
	}
	prefix, rest, ok := strings.Cut(token, ":")
	if !ok {
		return token
	}
	if rest != "$" {
		return token
	}
	switch prefix {
	case "map", "ringbuf":
		return prefix + ":" + mapName
	default:
		return token
	}
}
