package capability

import (
	"fmt"

	"m31labs.dev/horizon/ir"
)

func FromIR(program ir.Program) Manifest {
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
