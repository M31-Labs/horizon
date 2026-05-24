package capability

import (
	"fmt"

	"m31labs.dev/horizon/ir"
)

func FromIR(program ir.Program) Manifest {
	manifest := NewManifest(program.Package)
	for _, fn := range program.Functions {
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
			Section:      manifestSection(fn.Section),
			Capabilities: caps,
		})
	}
	for _, cap := range program.Capabilities {
		manifest.Capabilities = append(manifest.Capabilities, Capability{
			Name:    cap.Name,
			Kind:    string(cap.Kind),
			Danger:  string(cap.Danger),
			Program: cap.Program,
			Section: cap.Section,
			Emits:   cap.Emits,
			Maps: MapAccess{
				Read:   cap.Maps.Read,
				Write:  cap.Maps.Write,
				Events: cap.Maps.Events,
			},
		})
	}
	for _, m := range program.Maps {
		manifest.Maps = append(manifest.Maps, Map{
			Name:  m.Name,
			Kind:  string(m.Kind),
			Key:   manifestType(m.Key),
			Value: manifestType(m.Val),
		})
	}
	for _, typ := range program.Structs {
		schema := TypeSchema{Name: typ.Name, Kind: "struct"}
		for _, field := range typ.Fields {
			schema.Fields = append(schema.Fields, FieldSchema{
				Name: field.Name,
				Type: manifestType(field.Type),
			})
		}
		manifest.Types = append(manifest.Types, schema)
	}
	return manifest
}

func manifestSection(section ir.Section) string {
	if section.Kind == ir.ProgramTracepoint && section.Attach != "" {
		return "tracepoint/" + section.Attach
	}
	if section.Kind == ir.ProgramXDP {
		return "xdp"
	}
	if (section.Kind == ir.ProgramKprobe || section.Kind == ir.ProgramKretprobe) && section.Attach != "" {
		return string(section.Kind) + "/" + section.Attach
	}
	return section.Name
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
