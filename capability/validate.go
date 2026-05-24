package capability

import (
	"fmt"
	"strings"
)

func Validate(m Manifest) error {
	if m.Schema == "" {
		return fmt.Errorf("capability manifest schema is required")
	}
	if m.Schema != SchemaV0 {
		return fmt.Errorf("unsupported capability manifest schema %q", m.Schema)
	}
	if m.Package == "" {
		return fmt.Errorf("capability manifest package is required")
	}
	programs := map[string]bool{}
	for _, program := range m.Programs {
		if program.Name == "" {
			return fmt.Errorf("capability manifest program name is required")
		}
		if program.Kind == "" {
			return fmt.Errorf("capability manifest program %q kind is required", program.Name)
		}
		if program.Section == "" {
			return fmt.Errorf("capability manifest program %q section is required", program.Name)
		}
		programs[program.Name] = true
	}
	maps := map[string]Map{}
	for _, mapSpec := range m.Maps {
		if mapSpec.Name == "" {
			return fmt.Errorf("capability manifest map name is required")
		}
		if mapSpec.Kind == "" {
			return fmt.Errorf("capability manifest map %q kind is required", mapSpec.Name)
		}
		if mapSpec.Value == "" {
			return fmt.Errorf("capability manifest map %q value type is required", mapSpec.Name)
		}
		maps[mapSpec.Name] = mapSpec
	}
	types := map[string]bool{}
	for _, typ := range m.Types {
		if typ.Name == "" {
			return fmt.Errorf("capability manifest type name is required")
		}
		if typ.Kind == "" {
			return fmt.Errorf("capability manifest type %q kind is required", typ.Name)
		}
		if typ.Size != nil && *typ.Size < 0 {
			return fmt.Errorf("capability manifest type %q size must be non-negative", typ.Name)
		}
		if typ.Align != nil && *typ.Align <= 0 {
			return fmt.Errorf("capability manifest type %q align must be positive", typ.Name)
		}
		types[typ.Name] = true
	}
	for _, typ := range m.Types {
		for _, field := range typ.Fields {
			if field.Name == "" {
				return fmt.Errorf("capability manifest type %q field name is required", typ.Name)
			}
			if field.Type == "" {
				return fmt.Errorf("capability manifest type %q field %q type is required", typ.Name, field.Name)
			}
			if field.Offset != nil {
				if *field.Offset < 0 {
					return fmt.Errorf("capability manifest type %q field %q offset must be non-negative", typ.Name, field.Name)
				}
				if typ.Size != nil && *field.Offset > *typ.Size {
					return fmt.Errorf("capability manifest type %q field %q offset exceeds type size", typ.Name, field.Name)
				}
			}
			if err := validateTypeRefs(field.Type, types); err != nil {
				return err
			}
		}
	}
	validateSchemaRefs := len(types) > 0
	if validateSchemaRefs {
		for _, mapSpec := range maps {
			if err := validateTypeRefs(mapSpec.Key, types); err != nil {
				return fmt.Errorf("map %q key: %w", mapSpec.Name, err)
			}
			if err := validateTypeRefs(mapSpec.Value, types); err != nil {
				return fmt.Errorf("map %q value: %w", mapSpec.Name, err)
			}
		}
	}
	for _, cap := range m.Capabilities {
		if cap.Name == "" {
			return fmt.Errorf("capability manifest capability name is required")
		}
		if cap.Kind == "" {
			return fmt.Errorf("capability %q kind is required", cap.Name)
		}
		if cap.Danger == "" {
			return fmt.Errorf("capability %q danger is required", cap.Name)
		}
		if cap.Program == "" {
			return fmt.Errorf("capability %q program is required", cap.Name)
		}
		if len(programs) > 0 && !programs[cap.Program] {
			return fmt.Errorf("capability %q references unknown program %q", cap.Name, cap.Program)
		}
		if cap.Section == "" {
			return fmt.Errorf("capability %q section is required", cap.Name)
		}
		if validateSchemaRefs && cap.Emits != "" {
			if err := validateTypeRefs(cap.Emits, types); err != nil {
				return fmt.Errorf("capability %q emits: %w", cap.Name, err)
			}
		}
		for _, name := range append(append([]string{}, cap.Maps.Read...), append(cap.Maps.Write, cap.Maps.Events...)...) {
			if len(maps) > 0 && maps[name].Name == "" {
				return fmt.Errorf("capability %q references unknown map %q", cap.Name, name)
			}
		}
	}
	return nil
}

func validateTypeRefs(typeName string, known map[string]bool) error {
	for _, ref := range typeRefs(typeName) {
		if isBuiltinType(ref) {
			continue
		}
		if !known[ref] {
			return fmt.Errorf("type %q is missing from manifest types", ref)
		}
	}
	return nil
}

func typeRefs(typeName string) []string {
	typeName = strings.TrimSpace(typeName)
	for strings.HasPrefix(typeName, "*") {
		typeName = strings.TrimPrefix(typeName, "*")
	}
	if strings.HasPrefix(typeName, "[") {
		if end := strings.Index(typeName, "]"); end >= 0 {
			return typeRefs(typeName[end+1:])
		}
	}
	if typeName == "" {
		return nil
	}
	return []string{typeName}
}

func isBuiltinType(name string) bool {
	switch name {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool":
		return true
	default:
		return false
	}
}
