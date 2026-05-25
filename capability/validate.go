package capability

import (
	"errors"
	"fmt"
	"strconv"
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
	if err := validateManifestHeader(m); err != nil {
		return err
	}
	if err := validateRequirements(m.Requirements); err != nil {
		return err
	}
	programs, err := indexManifestPrograms(m.Programs)
	if err != nil {
		return err
	}
	maps, err := indexManifestMaps(m.Maps)
	if err != nil {
		return err
	}
	types, err := indexManifestTypes(m.Types)
	if err != nil {
		return err
	}
	if err := validateManifestTypeFields(m.Types, types); err != nil {
		return err
	}
	if len(types) > 0 {
		if err := validateManifestMapTypeRefs(maps, types); err != nil {
			return err
		}
	}
	return validateManifestCapabilities(m.Capabilities, programs, maps, types)
}

func validateManifestHeader(m Manifest) error {
	if m.Schema == "" {
		return validationErrorf("capability manifest schema is required")
	}
	if m.Schema != SchemaV0 {
		return validationErrorf("unsupported capability manifest schema %q", m.Schema)
	}
	if m.Package == "" {
		return validationErrorf("capability manifest package is required")
	}
	return nil
}

func indexManifestPrograms(programSpecs []Program) (map[string]Program, error) {
	programs := map[string]Program{}
	for _, program := range programSpecs {
		if program.Name == "" {
			return nil, validationErrorf("capability manifest program name is required")
		}
		if program.Kind == "" {
			return nil, validationErrorf("capability manifest program %q kind is required", program.Name)
		}
		if !validProgramKind(program.Kind) {
			return nil, validationErrorf("capability manifest program %q kind %q is not supported", program.Name, program.Kind)
		}
		if program.Section == "" {
			return nil, validationErrorf("capability manifest program %q section is required", program.Name)
		}
		programs[program.Name] = program
	}
	return programs, nil
}

func indexManifestMaps(mapSpecs []Map) (map[string]Map, error) {
	maps := map[string]Map{}
	for _, mapSpec := range mapSpecs {
		if mapSpec.Name == "" {
			return nil, validationErrorf("capability manifest map name is required")
		}
		if mapSpec.Kind == "" {
			return nil, validationErrorf("capability manifest map %q kind is required", mapSpec.Name)
		}
		if !validMapKind(mapSpec.Kind) {
			return nil, validationErrorf("capability manifest map %q kind %q is not supported", mapSpec.Name, mapSpec.Kind)
		}
		if mapSpec.Value == "" {
			return nil, validationErrorf("capability manifest map %q value type is required", mapSpec.Name)
		}
		if mapSpec.MaxEntries != "" {
			value, err := strconv.ParseUint(mapSpec.MaxEntries, 0, 32)
			if err != nil || value == 0 {
				return nil, validationErrorf("capability manifest map %q max_entries must be a positive integer literal", mapSpec.Name)
			}
			if mapSpec.Kind == "ringbuf" && value&(value-1) != 0 {
				return nil, validationErrorf("capability manifest ringbuf map %q max_entries must be a power of two", mapSpec.Name)
			}
		}
		maps[mapSpec.Name] = mapSpec
	}
	return maps, nil
}

func indexManifestTypes(typeSpecs []TypeSchema) (map[string]bool, error) {
	types := map[string]bool{}
	for _, typ := range typeSpecs {
		if typ.Name == "" {
			return nil, validationErrorf("capability manifest type name is required")
		}
		if typ.Kind == "" {
			return nil, validationErrorf("capability manifest type %q kind is required", typ.Name)
		}
		if typ.Kind != "struct" {
			return nil, validationErrorf("capability manifest type %q kind %q is not supported", typ.Name, typ.Kind)
		}
		if typ.Size != nil && *typ.Size < 0 {
			return nil, validationErrorf("capability manifest type %q size must be non-negative", typ.Name)
		}
		if typ.Align != nil && *typ.Align <= 0 {
			return nil, validationErrorf("capability manifest type %q align must be positive", typ.Name)
		}
		types[typ.Name] = true
	}
	return types, nil
}

func validateManifestTypeFields(typeSpecs []TypeSchema, types map[string]bool) error {
	for _, typ := range typeSpecs {
		for _, field := range typ.Fields {
			if err := validateManifestTypeField(typ, field, types); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateManifestTypeField(typ TypeSchema, field FieldSchema, types map[string]bool) error {
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
	return nil
}

func validateManifestMapTypeRefs(maps map[string]Map, types map[string]bool) error {
	for _, mapSpec := range maps {
		if err := validateTypeRefs(mapSpec.Key, types); err != nil {
			return validationErrorf("map %q key: %v", mapSpec.Name, err)
		}
		if err := validateTypeRefs(mapSpec.Value, types); err != nil {
			return validationErrorf("map %q value: %v", mapSpec.Name, err)
		}
	}
	return nil
}

func validateManifestCapabilities(caps []Capability, programs map[string]Program, maps map[string]Map, types map[string]bool) error {
	validateSchemaRefs := len(types) > 0
	for _, cap := range caps {
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
		program, ok := programs[cap.Program]
		if len(programs) > 0 && !ok {
			return validationErrorf("capability %q references unknown program %q", cap.Name, cap.Program)
		}
		if cap.Section == "" {
			return validationErrorf("capability %q section is required", cap.Name)
		}
		if ok {
			if err := validateCapabilityNamespace(cap, program); err != nil {
				return err
			}
		}
		if err := validateRequirements(cap.Requirements); err != nil {
			return validationErrorf("capability %q requirements: %v", cap.Name, err)
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

func validateCapabilityNamespace(cap Capability, program Program) error {
	if cap.Name == "" || !strings.HasPrefix(cap.Name, "kernel.") {
		return nil
	}
	want := expectedKernelCapabilityPrefix(program)
	if want == "" || strings.HasPrefix(cap.Name, want) {
		return nil
	}
	return validationErrorf("capability %q does not match %s program %q", cap.Name, programSectionDescription(program), cap.Program)
}

func expectedKernelCapabilityPrefix(program Program) string {
	attach := manifestProgramAttach(program)
	switch program.Kind {
	case "tracepoint":
		if attach == "sched:sched_process_exec" {
			return "kernel.process.exec."
		}
	case "xdp":
		return "kernel.network.xdp."
	case "tc":
		return "kernel.network.tc."
	case "cgroup":
		if attach == "connect4" || attach == "connect6" {
			return "kernel.network.connect."
		}
	case "lsm":
		if attach == "file_open" {
			return "kernel.file.open."
		}
	case "kprobe", "kretprobe":
		switch attach {
		case "do_sys_openat2":
			return "kernel.file.open."
		case "tcp_v4_connect":
			return "kernel.network.tcp.connect."
		}
	}
	return ""
}

func manifestProgramAttach(program Program) string {
	if program.Attach != "" {
		return program.Attach
	}
	prefix := program.Kind + "/"
	if strings.HasPrefix(program.Section, prefix) {
		return strings.TrimPrefix(program.Section, prefix)
	}
	return ""
}

func programSectionDescription(program Program) string {
	if program.Section != "" {
		return program.Section
	}
	if program.Attach != "" {
		return program.Kind + "/" + program.Attach
	}
	return program.Kind
}

func validationErrorf(format string, args ...any) error {
	return Error{Err: fmt.Errorf(format, args...)}
}

func validProgramKind(kind string) bool {
	switch kind {
	case "tracepoint", "xdp", "tc", "cgroup", "lsm", "kprobe", "kretprobe":
		return true
	default:
		return false
	}
}

func validMapKind(kind string) bool {
	switch kind {
	case "ringbuf", "hash", "array", "percpu_hash", "percpu_array", "lru_hash", "lru_percpu_hash":
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

func validateRequirements(reqs *Requirements) error {
	if reqs == nil {
		return nil
	}
	if reqs.MinKernel == "" {
		if len(reqs.Programs) > 0 || len(reqs.Maps) > 0 || len(reqs.Helpers) > 0 {
			return validationErrorf("requirements min_kernel is required when feature requirements are present")
		}
	} else if !validKernelVersion(reqs.MinKernel) {
		return validationErrorf("requirements min_kernel %q must use major.minor kernel version form", reqs.MinKernel)
	}
	for _, group := range []struct {
		name  string
		items []FeatureRequirement
		valid func(string) bool
	}{
		{name: "program", items: reqs.Programs, valid: validProgramKind},
		{name: "map", items: reqs.Maps, valid: validMapKind},
		{name: "helper", items: reqs.Helpers, valid: validHelperRequirement},
	} {
		if err := validateFeatureRequirements(group.name, group.items, group.valid); err != nil {
			return err
		}
		for _, item := range group.items {
			if reqs.MinKernel != "" && compareKernelVersion(reqs.MinKernel, item.MinKernel) < 0 {
				return validationErrorf("requirements min_kernel %q is lower than %s %q requirement %q", reqs.MinKernel, group.name, item.Name, item.MinKernel)
			}
		}
	}
	if err := validateStringRequirements("permission", reqs.Permissions, validPermissionRequirement); err != nil {
		return err
	}
	if err := validateStringRequirements("feature", reqs.Features, validHostFeatureRequirement); err != nil {
		return err
	}
	return nil
}

func validateFeatureRequirements(kind string, items []FeatureRequirement, valid func(string) bool) error {
	seen := map[string]bool{}
	for _, item := range items {
		if item.Name == "" {
			return validationErrorf("%s requirement name is required", kind)
		}
		if !valid(item.Name) {
			return validationErrorf("%s requirement %q is not supported", kind, item.Name)
		}
		if seen[item.Name] {
			return validationErrorf("%s requirement %q is declared more than once", kind, item.Name)
		}
		seen[item.Name] = true
		if item.MinKernel == "" {
			return validationErrorf("%s requirement %q min_kernel is required", kind, item.Name)
		}
		if !validKernelVersion(item.MinKernel) {
			return validationErrorf("%s requirement %q min_kernel %q must use major.minor kernel version form", kind, item.Name, item.MinKernel)
		}
	}
	return nil
}

func validateStringRequirements(kind string, items []string, valid func(string) bool) error {
	seen := map[string]bool{}
	for _, item := range items {
		if item == "" {
			return validationErrorf("%s requirement name is required", kind)
		}
		if !valid(item) {
			return validationErrorf("%s requirement %q is not supported", kind, item)
		}
		if seen[item] {
			return validationErrorf("%s requirement %q is declared more than once", kind, item)
		}
		seen[item] = true
	}
	return nil
}

func validKernelVersion(version string) bool {
	_, _, ok := parseKernelVersion(version)
	return ok
}

func validHelperRequirement(name string) bool {
	return helperMinKernel(name) != ""
}

func validPermissionRequirement(name string) bool {
	switch name {
	case "bpf_program_load", "cgroup_admin", "lsm_admin", "net_admin", "perf_event_open":
		return true
	default:
		return false
	}
}

func validHostFeatureRequirement(name string) bool {
	switch name {
	case "bpf_lsm", "cgroup_v2", "kprobes", "netdev_xdp", "tc_clsact", "tracefs":
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
