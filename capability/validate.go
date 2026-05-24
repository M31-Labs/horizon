package capability

import (
	"errors"
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
)

type Error struct {
	Err error
}

func (e Error) Error() string {
	if e.Err == nil {
		return "validate capability manifest"
	}
	return "validate capability manifest: " + e.Err.Error()
}

func (e Error) Unwrap() error {
	return e.Err
}

func DiagnosticForError(err error) (diag.Diagnostic, bool) {
	var capErr Error
	if !errors.As(err, &capErr) {
		return diag.Diagnostic{}, false
	}
	message := "invalid capability manifest"
	if capErr.Err != nil {
		message += ": " + capErr.Err.Error()
	}
	return diag.Diagnostic{
		Code:     "HZN3300",
		Severity: diag.SeverityError,
		Message:  message,
		Notes: []string{
			"Capability manifests are the Continuum-facing contract for generated eBPF artifacts.",
		},
		Suggest: "keep capability, program, map, danger, and type metadata within the Horizon capability schema",
	}, true
}

func Validate(m Manifest) error {
	if m.Schema == "" {
		return validationErrorf("capability manifest schema is required")
	}
	if m.Schema != SchemaV0 {
		return validationErrorf("unsupported capability manifest schema %q", m.Schema)
	}
	if m.Package == "" {
		return validationErrorf("capability manifest package is required")
	}
	programs := map[string]bool{}
	for _, program := range m.Programs {
		if program.Name == "" {
			return validationErrorf("capability manifest program name is required")
		}
		if program.Kind == "" {
			return validationErrorf("capability manifest program %q kind is required", program.Name)
		}
		if !validProgramKind(program.Kind) {
			return validationErrorf("capability manifest program %q kind %q is not supported", program.Name, program.Kind)
		}
		if program.Section == "" {
			return validationErrorf("capability manifest program %q section is required", program.Name)
		}
		programs[program.Name] = true
	}
	maps := map[string]Map{}
	for _, mapSpec := range m.Maps {
		if mapSpec.Name == "" {
			return validationErrorf("capability manifest map name is required")
		}
		if mapSpec.Kind == "" {
			return validationErrorf("capability manifest map %q kind is required", mapSpec.Name)
		}
		if !validMapKind(mapSpec.Kind) {
			return validationErrorf("capability manifest map %q kind %q is not supported", mapSpec.Name, mapSpec.Kind)
		}
		if mapSpec.Value == "" {
			return validationErrorf("capability manifest map %q value type is required", mapSpec.Name)
		}
		maps[mapSpec.Name] = mapSpec
	}
	types := map[string]bool{}
	for _, typ := range m.Types {
		if typ.Name == "" {
			return validationErrorf("capability manifest type name is required")
		}
		if typ.Kind == "" {
			return validationErrorf("capability manifest type %q kind is required", typ.Name)
		}
		if typ.Kind != "struct" {
			return validationErrorf("capability manifest type %q kind %q is not supported", typ.Name, typ.Kind)
		}
		if typ.Size != nil && *typ.Size < 0 {
			return validationErrorf("capability manifest type %q size must be non-negative", typ.Name)
		}
		if typ.Align != nil && *typ.Align <= 0 {
			return validationErrorf("capability manifest type %q align must be positive", typ.Name)
		}
		types[typ.Name] = true
	}
	for _, typ := range m.Types {
		for _, field := range typ.Fields {
			if field.Name == "" {
				return validationErrorf("capability manifest type %q field name is required", typ.Name)
			}
			if field.Type == "" {
				return validationErrorf("capability manifest type %q field %q type is required", typ.Name, field.Name)
			}
			if field.Offset != nil {
				if *field.Offset < 0 {
					return validationErrorf("capability manifest type %q field %q offset must be non-negative", typ.Name, field.Name)
				}
				if typ.Size != nil && *field.Offset > *typ.Size {
					return validationErrorf("capability manifest type %q field %q offset exceeds type size", typ.Name, field.Name)
				}
			}
			if err := validateTypeRefs(field.Type, types); err != nil {
				return validationErrorf("capability manifest type %q field %q: %v", typ.Name, field.Name, err)
			}
		}
	}
	validateSchemaRefs := len(types) > 0
	if validateSchemaRefs {
		for _, mapSpec := range maps {
			if err := validateTypeRefs(mapSpec.Key, types); err != nil {
				return validationErrorf("map %q key: %v", mapSpec.Name, err)
			}
			if err := validateTypeRefs(mapSpec.Value, types); err != nil {
				return validationErrorf("map %q value: %v", mapSpec.Name, err)
			}
		}
	}
	for _, cap := range m.Capabilities {
		if cap.Name == "" {
			return validationErrorf("capability manifest capability name is required")
		}
		if cap.Kind == "" {
			return validationErrorf("capability %q kind is required", cap.Name)
		}
		if cap.Kind != "source" {
			return validationErrorf("capability %q kind %q is not supported", cap.Name, cap.Kind)
		}
		if cap.Danger == "" {
			return validationErrorf("capability %q danger is required", cap.Name)
		}
		if !validDangerLevel(cap.Danger) {
			return validationErrorf("capability %q danger %q is not supported", cap.Name, cap.Danger)
		}
		if cap.Program == "" {
			return validationErrorf("capability %q program is required", cap.Name)
		}
		if len(programs) > 0 && !programs[cap.Program] {
			return validationErrorf("capability %q references unknown program %q", cap.Name, cap.Program)
		}
		if cap.Section == "" {
			return validationErrorf("capability %q section is required", cap.Name)
		}
		if validateSchemaRefs && cap.Emits != "" {
			if err := validateTypeRefs(cap.Emits, types); err != nil {
				return validationErrorf("capability %q emits: %v", cap.Name, err)
			}
		}
		for _, name := range append(append([]string{}, cap.Maps.Read...), append(cap.Maps.Write, cap.Maps.Events...)...) {
			if len(maps) > 0 && maps[name].Name == "" {
				return validationErrorf("capability %q references unknown map %q", cap.Name, name)
			}
		}
	}
	return nil
}

func validationErrorf(format string, args ...any) error {
	return Error{Err: fmt.Errorf(format, args...)}
}

func validProgramKind(kind string) bool {
	switch kind {
	case "tracepoint", "xdp", "kprobe", "kretprobe":
		return true
	default:
		return false
	}
}

func validMapKind(kind string) bool {
	switch kind {
	case "ringbuf", "hash", "array":
		return true
	default:
		return false
	}
}

func validDangerLevel(danger string) bool {
	switch danger {
	case "observe", "mutate", "drop", "block", "privileged":
		return true
	default:
		return false
	}
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
