package capability

import (
	"fmt"

	"m31labs.dev/horizon/ir"
)

func FromIR(program ir.Program) Manifest {
	// If the program has declarations spanning multiple Origin tags (the
	// cross-package build path landed in Phase 2 Subtask 4b), route through
	// the aggregator so manifest names are qualified consistently. Single-
	// package builds (every Origin == "") continue through the legacy
	// emission path unchanged so existing goldens are bit-stable.
	// (roadmap #21 Phase 2 Subtask 5b.)
	if programHasMixedOrigins(program) {
		return fromIRAggregated(program)
	}
	return emitManifest(program, "")
}

// programHasMixedOrigins reports whether any declaration in the program
// carries a non-empty Origin tag. The check is cheap (a single linear pass
// over each declaration slice) so the single-package hot path pays only
// a constant per-build cost.
func programHasMixedOrigins(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Origin != "" {
			return true
		}
	}
	for _, m := range program.Maps {
		if m.Origin != "" {
			return true
		}
	}
	for _, c := range program.Capabilities {
		if c.Origin != "" {
			return true
		}
	}
	for _, s := range program.Structs {
		if s.Origin != "" {
			return true
		}
	}
	return false
}

// fromIRAggregated splits the merged IR Program into one partial manifest
// per origin (root + each dep alias), then runs AggregateManifests to
// produce the qualified-name output. Splitting first keeps emitManifest's
// per-declaration logic identical between single- and multi-package builds;
// AggregateManifests owns all qualified-name composition and conflict
// detection.
func fromIRAggregated(program ir.Program) Manifest {
	originSet := map[string]bool{"": true}
	for _, fn := range program.Functions {
		originSet[fn.Origin] = true
	}
	for _, m := range program.Maps {
		originSet[m.Origin] = true
	}
	for _, c := range program.Capabilities {
		originSet[c.Origin] = true
	}
	for _, s := range program.Structs {
		originSet[s.Origin] = true
	}

	manifests := make([]Manifest, 0, len(originSet))
	// Emit the root first so its (unqualified) capability ordering wins
	// the section-owner check inside AggregateManifests.
	manifests = append(manifests, emitManifest(filterByOrigin(program, ""), ""))
	for origin := range originSet {
		if origin == "" {
			continue
		}
		manifests = append(manifests, emitManifest(filterByOrigin(program, origin), origin))
	}
	out, _ := AggregateManifests(manifests, program.Package)
	// FromIR's signature predates aggregation diagnostics; surfacing them
	// is the caller's job through the compiler.Result diagnostic channel
	// (Subtask 5b's plan defers wiring to a future task). For now the
	// aggregator's diagnostics are dropped here — TestAnalyzePathTwoPackageBuild
	// already pins that the upstream cross-package collisions surface via
	// ir.MergeWithDiagnostics's HZN156x codes, which is the source of
	// truth for collisions; aggregator HZN1553/HZN1560/HZN1564/HZN1565
	// codes are redundant for now and reserved for Task 6 wiring.
	return out
}

// filterByOrigin returns a copy of program restricted to declarations whose
// Origin matches the requested value. emitManifest then runs on this
// shrunk view so each partial manifest only sees its own package's decls.
// The view shares slice elements with program — we never mutate them, so
// the copy stays cheap.
func filterByOrigin(program ir.Program, origin string) ir.Program {
	out := ir.Program{
		Package: program.Package,
	}
	for _, fn := range program.Functions {
		if fn.Origin == origin {
			out.Functions = append(out.Functions, fn)
		}
	}
	for _, m := range program.Maps {
		if m.Origin == origin {
			out.Maps = append(out.Maps, m)
		}
	}
	for _, c := range program.Capabilities {
		if c.Origin == origin {
			out.Capabilities = append(out.Capabilities, c)
		}
	}
	for _, s := range program.Structs {
		if s.Origin == origin {
			out.Structs = append(out.Structs, s)
		}
	}
	for _, c := range program.Constants {
		if c.Origin == origin {
			out.Constants = append(out.Constants, c)
		}
	}
	return out
}

// emitManifest is the single-origin emission core extracted from the legacy
// FromIR body. The origin parameter, when non-empty, is stamped onto every
// emitted Capability / Map so the aggregator can compose qualified names
// downstream. Single-package callers pass origin == "" and get the same
// manifest shape they always had.
func emitManifest(program ir.Program, origin string) Manifest {
	manifest := NewManifest(program.Package)
	requirements := requirementsFromIR(program)
	if requirements.MinKernel != "" {
		manifest.Requirements = &requirements
	}
	functions := functionsByName(program.Functions)
	for _, fn := range program.Functions {
		if fn.Section.Kind == "" {
			continue
		}
		var caps []string
		for _, cap := range program.Capabilities {
			if cap.Program == fn.Name {
				caps = append(caps, cap.Name)
			}
		}
		manifest.Programs = append(manifest.Programs, Program{
			Name:         fn.Name,
			Kind:         string(fn.Section.Kind),
			Attach:       fn.Section.Attach,
			Section:      fn.Section.ManifestName(),
			Capabilities: caps,
		})
	}
	for _, cap := range program.Capabilities {
		axes := cap.Axes
		if axes.Mode == "" && axes.Scope == "" && axes.Reversibility == "" {
			// Fall back to deriving axes from the flat DangerLevel for
			// callers that haven't yet set Axes explicitly.
			irAxes := cap.Danger.Axes()
			axes = ir.DangerAxes{
				Mode:          irAxes.Mode,
				Scope:         irAxes.Scope,
				Reversibility: irAxes.Reversibility,
			}
		}
		out := Capability{
			Name: cap.Name,
			Kind: string(cap.Kind),
			Danger: DangerAxes{
				Mode:          axes.Mode,
				Scope:         axes.Scope,
				Reversibility: axes.Reversibility,
			},
			Program: cap.Program,
			Section: cap.Section,
			Emits:   cap.Emits,
			Maps: MapAccess{
				Read:   cap.Maps.Read,
				Write:  cap.Maps.Write,
				Events: cap.Maps.Events,
			},
			Origin: origin,
		}
		if fn, ok := functions[cap.Program]; ok {
			requirements := requirementsForCapability(program, cap, fn)
			if requirements.MinKernel != "" {
				out.Requirements = &requirements
			}
			out.HelperEffects = ComputeHelperEffectsForFunction(program, fn)
		}
		manifest.Capabilities = append(manifest.Capabilities, out)
	}
	for _, m := range program.Maps {
		manifest.Maps = append(manifest.Maps, Map{
			Name:               m.Name,
			Kind:               string(m.Kind),
			Key:                manifestType(m.Key),
			Value:              manifestType(m.Val),
			MaxEntries:         m.MaxEntries,
			SteadyStateEntries: m.SteadyStateEntries,
			AccessFreq:         m.AccessFreq,
			Origin:             origin,
		})
	}
	structs := ir.StructsByName(program.Structs)
	for _, typ := range program.Structs {
		schema := TypeSchema{Name: typ.Name, Kind: "struct"}
		offsets := map[string]int{}
		if layout, ok := ir.StructLayout(typ, structs); ok {
			schema.Size = intPtr(layout.Size)
			schema.Align = intPtr(layout.Align)
			for _, field := range layout.Fields {
				offsets[field.Name] = field.Offset
			}
		}
		for _, field := range typ.Fields {
			fieldSchema := FieldSchema{
				Name: field.Name,
				Type: manifestType(field.Type),
			}
			if offset, ok := offsets[field.Name]; ok {
				fieldSchema.Offset = intPtr(offset)
			}
			schema.Fields = append(schema.Fields, fieldSchema)
		}
		manifest.Types = append(manifest.Types, schema)
	}
	return manifest
}

func functionsByName(functions []ir.Function) map[string]ir.Function {
	out := make(map[string]ir.Function, len(functions))
	for _, fn := range functions {
		out[fn.Name] = fn
	}
	return out
}


func manifestType(typ ir.Type) string {
	if typ.Ptr {
		if typ.Elem != nil {
			return "*" + manifestType(*typ.Elem)
		}
		if typ.Name != "" {
			return "*" + typ.Name
		}
	}
	if typ.Len != "" && typ.Elem != nil {
		return fmt.Sprintf("[%s]%s", typ.Len, manifestType(*typ.Elem))
	}
	if typ.Name != "" {
		return typ.Name
	}
	return ""
}

func intPtr(value int) *int {
	return &value
}
