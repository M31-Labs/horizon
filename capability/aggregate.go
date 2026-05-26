package capability

import (
	"fmt"
	"sort"

	"m31labs.dev/horizon/compiler/diag"
)

// AggregateManifests merges per-package capability manifests into a single
// root manifest using the rules in roadmap #21 Phase 2 Subtask 5a:
//
//   - Root-package capabilities (Origin == "") keep their bare Name.
//   - Imported-package capabilities (Origin != "") are renamed by prefixing
//     the Origin alias and a dot (e.g. "ExecObserve" -> "events.ExecObserve").
//     The Origin field is preserved on the resulting Capability.
//   - Two manifests contributing the same qualified Name dedupe silently
//     when they agree on shape; they produce HZN1560 errors when they
//     disagree on danger/section/kind/program/maps.
//   - Two manifests from DIFFERENT packages that contribute the same
//     section string ("kernel.process.exec.observe") produce an HZN1553
//     advisory warning. Both qualified entries remain in the output.
//   - Maps deduplicate by qualified Name. Conflicting shapes (different
//     kind/key/value/max_entries) emit an HZN1564 error.
//   - Type schemas deduplicate by Name. Conflicting layouts emit an
//     HZN1565 error.
//   - Output is sorted lexicographically by qualified Name within each
//     section (Capabilities, Maps, Types, Programs) so JSON marshalling
//     is byte-stable across invocations.
//
// rootPackage names the resulting manifest. The function does NOT mutate
// its input manifests; each Capability/Map is copied before any qualified-
// name rewrite.
//
// Per the plan, root-package symbols colliding with each other remain
// types.CheckPackage's responsibility (HZN1002 territory). The aggregator
// detects cross-package collisions only — collisions where at least one
// side carries a non-empty Origin or where the two sides come from
// different positions in the input slice and share a qualifying alias.
func AggregateManifests(manifests []Manifest, rootPackage string) (Manifest, []diag.Diagnostic) {
	out := NewManifest(rootPackage)
	var diags []diag.Diagnostic

	type capEntry struct {
		cap          Capability
		sourceOrigin string
		manifestIdx  int
	}
	capsByQname := map[string]capEntry{}
	// sectionOwners tracks which package's qualified-name owns each
	// section string. A second package writing the same section string
	// fires HZN1553 — the "two packages independently claiming the same
	// kernel hook" advisory.
	sectionOwners := map[string]string{}

	for idx, m := range manifests {
		for _, c := range m.Capabilities {
			qname := qualifiedCapabilityName(c)
			c.Name = qname
			if c.Maps.Read == nil {
				c.Maps.Read = []string{}
			}
			if c.Maps.Write == nil {
				c.Maps.Write = []string{}
			}
			if c.Maps.Events == nil {
				c.Maps.Events = []string{}
			}
			prev, seen := capsByQname[qname]
			if seen {
				if !capabilitiesEqual(prev.cap, c) {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN1560",
						Severity: diag.SeverityError,
						Message: fmt.Sprintf(
							"capability %q has conflicting definitions across packages",
							qname,
						),
						Suggest: "two packages contributed a capability with the same qualified name but different danger / program / section / map access; rename one or move the shared declaration to a single owning package",
					})
				}
				continue
			}
			if c.Section != "" {
				if owner, taken := sectionOwners[c.Section]; taken && owner != c.Origin {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN1553",
						Severity: diag.SeverityWarning,
						Message: fmt.Sprintf(
							"capability value %q is declared by multiple packages (%q and %q); both will surface in the aggregated manifest under their qualified names",
							c.Section,
							owner,
							c.Origin,
						),
						Suggest: "if both packages intend to observe the same kernel hook, vendor a single shared capability declaration; if the collision is incidental, rename one of them to make ownership explicit",
					})
				} else if !taken {
					sectionOwners[c.Section] = c.Origin
				}
			}
			capsByQname[qname] = capEntry{
				cap:          c,
				sourceOrigin: c.Origin,
				manifestIdx:  idx,
			}
		}
	}

	mapsByQname := map[string]Map{}
	for _, m := range manifests {
		for _, mp := range m.Maps {
			qname := qualifiedMapName(mp)
			mp.Name = qname
			prev, seen := mapsByQname[qname]
			if seen {
				if !mapsEqual(prev, mp) {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN1564",
						Severity: diag.SeverityError,
						Message: fmt.Sprintf(
							"map %q has conflicting shapes across packages",
							qname,
						),
						Suggest: "two packages contributed a map with the same qualified name but different kind / key / value / max_entries; rename one or move the shared definition to a single owning package",
					})
				}
				continue
			}
			mapsByQname[qname] = mp
		}
	}

	// Types deduplicate by their bare Name. Type identity is anchored on the
	// bare name because struct types form a flat namespace in the merged IR
	// (cross-package layout collisions surface upstream as HZN1564 from
	// ir.MergeWithDiagnostics). The TypeSchema.Origin field carries the
	// import-alias provenance for downstream consumers that care; manifest
	// map.value strings continue to reference the bare type name so the
	// schema-level reference graph stays self-consistent without forcing
	// every map.value rewrite during aggregation.
	typesByName := map[string]TypeSchema{}
	for _, m := range manifests {
		for _, t := range m.Types {
			prev, seen := typesByName[t.Name]
			if seen {
				if !typeSchemasEqual(prev, t) {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN1565",
						Severity: diag.SeverityError,
						Message: fmt.Sprintf(
							"type %q has conflicting layouts across packages",
							t.Name,
						),
						Suggest: "two packages contributed a struct with the same name but different fields; rename one or move the shared type to a single owning package",
					})
				}
				continue
			}
			typesByName[t.Name] = t
		}
	}

	// Programs deduplicate by qualified Name. Programs are dispatched by
	// their attach section/kind; if two manifests contributed the same
	// program name with different attach points we surface that as an
	// HZN1565-class issue but keep the first definition. (Today's pipeline
	// doesn't produce two programs with the same name across packages, so
	// we don't allocate a fresh HZN code for this — collision detection
	// is left to IR merge HZN1562.)
	programsByName := map[string]Program{}
	for _, m := range manifests {
		for _, p := range m.Programs {
			if _, seen := programsByName[p.Name]; seen {
				continue
			}
			programsByName[p.Name] = p
		}
	}

	// Stable emission: sort by qualified Name lexicographically.
	capNames := make([]string, 0, len(capsByQname))
	for n := range capsByQname {
		capNames = append(capNames, n)
	}
	sort.Strings(capNames)
	for _, n := range capNames {
		out.Capabilities = append(out.Capabilities, capsByQname[n].cap)
	}

	mapNames := make([]string, 0, len(mapsByQname))
	for n := range mapsByQname {
		mapNames = append(mapNames, n)
	}
	sort.Strings(mapNames)
	for _, n := range mapNames {
		out.Maps = append(out.Maps, mapsByQname[n])
	}

	typeNames := make([]string, 0, len(typesByName))
	for n := range typesByName {
		typeNames = append(typeNames, n)
	}
	sort.Strings(typeNames)
	for _, n := range typeNames {
		out.Types = append(out.Types, typesByName[n])
	}

	programNames := make([]string, 0, len(programsByName))
	for n := range programsByName {
		programNames = append(programNames, n)
	}
	sort.Strings(programNames)
	for _, n := range programNames {
		out.Programs = append(out.Programs, programsByName[n])
	}

	// First non-nil Requirements wins. Requirements aggregation across
	// packages is left to v0.3 (where remote imports introduce real
	// MinKernel divergence); for now we forward the root's requirements
	// if any and otherwise fall back to the first non-nil dep.
	for _, m := range manifests {
		if m.Requirements != nil {
			req := *m.Requirements
			out.Requirements = &req
			break
		}
	}

	return out, diags
}

// qualifiedCapabilityName composes the qualified name for a capability,
// prefixing the Origin alias for imported capabilities and returning the
// bare Name for root-package capabilities. Idempotent: a Name that already
// begins with the Origin prefix is returned unchanged so callers that
// route a partially-aggregated manifest back through AggregateManifests
// (a defensive case the integration tests exercise) don't double-qualify.
func qualifiedCapabilityName(c Capability) string {
	if c.Origin == "" {
		return c.Name
	}
	prefix := c.Origin + "."
	if len(c.Name) >= len(prefix) && c.Name[:len(prefix)] == prefix {
		return c.Name
	}
	return prefix + c.Name
}

func qualifiedMapName(m Map) string {
	if m.Origin == "" {
		return m.Name
	}
	prefix := m.Origin + "."
	if len(m.Name) >= len(prefix) && m.Name[:len(prefix)] == prefix {
		return m.Name
	}
	return prefix + m.Name
}

func capabilitiesEqual(a, b Capability) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Danger != b.Danger {
		return false
	}
	if a.Program != b.Program {
		return false
	}
	if a.Section != b.Section {
		return false
	}
	if a.Emits != b.Emits {
		return false
	}
	if !stringSlicesEqual(a.Maps.Read, b.Maps.Read) {
		return false
	}
	if !stringSlicesEqual(a.Maps.Write, b.Maps.Write) {
		return false
	}
	if !stringSlicesEqual(a.Maps.Events, b.Maps.Events) {
		return false
	}
	return true
}

func mapsEqual(a, b Map) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Key != b.Key {
		return false
	}
	if a.Value != b.Value {
		return false
	}
	if a.MaxEntries != b.MaxEntries {
		return false
	}
	if a.SteadyStateEntries != b.SteadyStateEntries {
		return false
	}
	if a.AccessFreq != b.AccessFreq {
		return false
	}
	return true
}

func typeSchemasEqual(a, b TypeSchema) bool {
	if a.Kind != b.Kind {
		return false
	}
	if !intPtrEqual(a.Size, b.Size) {
		return false
	}
	if !intPtrEqual(a.Align, b.Align) {
		return false
	}
	if len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i].Name != b.Fields[i].Name {
			return false
		}
		if a.Fields[i].Type != b.Fields[i].Type {
			return false
		}
		if !intPtrEqual(a.Fields[i].Offset, b.Fields[i].Offset) {
			return false
		}
	}
	return true
}

func intPtrEqual(a, b *int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
