package bindgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"go/token"
	"strconv"
	"strings"
	"unicode"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

type Error struct {
	Stage   string
	Package string
	Err     error
}

func (e Error) Error() string {
	if e.Err == nil {
		return "generate Go bindings"
	}
	if e.Stage != "" {
		return fmt.Sprintf("generate Go bindings %s: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("generate Go bindings: %v", e.Err)
}

func (e Error) Unwrap() error {
	return e.Err
}

func DiagnosticForError(err error) (diag.Diagnostic, bool) {
	var bindErr Error
	if !errors.As(err, &bindErr) {
		return diag.Diagnostic{}, false
	}
	message := "cannot generate typed Go bindings"
	if bindErr.Err != nil {
		message += ": " + bindErr.Err.Error()
	}
	return diag.Diagnostic{
		Code:     "HZN3200",
		Severity: diag.SeverityError,
		Message:  message,
		Notes: []string{
			"Horizon generated bindings must be valid Go source.",
		},
		Suggest: "choose a valid generated Go package name and keep Horizon identifiers Go-bindable",
	}, true
}

func Generate(program ir.Program, packageName string) (string, error) {
	if packageName == "" {
		packageName = "bindings"
	}
	generator := newGenerator(program, packageName)
	return generator.generate()
}

type generator struct {
	program     ir.Program
	packageName string
	structs     map[string]ir.Struct
	b           bytes.Buffer
}

func newGenerator(program ir.Program, packageName string) *generator {
	return &generator{
		program:     program,
		packageName: packageName,
		structs:     ir.StructsByName(program.Structs),
	}
}

func (g *generator) generate() (string, error) {
	if err := g.validatePackage(); err != nil {
		return "", err
	}
	if err := g.validateGeneratedNames(); err != nil {
		return "", err
	}
	g.emitPackage()
	if err := g.emitCapabilityManifest(); err != nil {
		return "", err
	}
	g.emitTypes()
	g.emitObjects()
	g.emitLoadHelpers()
	g.emitClose()
	g.emitMapHelpers()
	g.emitAttachHelpers()
	return g.formatted()
}

func (g *generator) validatePackage() error {
	if validPackageName(g.packageName) {
		return nil
	}
	return Error{
		Stage:   "package",
		Package: g.packageName,
		Err:     fmt.Errorf("invalid Go package name %q", g.packageName),
	}
}

func (g *generator) validateGeneratedNames() error {
	if err := g.validateTopLevelNames(); err != nil {
		return err
	}
	if err := g.validateObjectFieldNames(); err != nil {
		return err
	}
	if err := g.validateObjectMethodNames(); err != nil {
		return err
	}
	return g.validateStructFieldNames()
}

func (g *generator) validateTopLevelNames() error {
	names := newGeneratedNameSet("top-level bindings")
	for _, reserved := range []string{"Objects", "LoadOptions", "LoadObjects", "LoadObjectsWithOptions", "CapabilityManifestJSON", "CapabilityManifest"} {
		names.reserve("generated "+reserved, reserved)
	}
	for _, decl := range g.program.Structs {
		if err := names.add(fmt.Sprintf("struct %q", decl.Name), exported(decl.Name)); err != nil {
			return g.identifierError(err)
		}
	}
	return nil
}

func (g *generator) validateObjectFieldNames() error {
	names := newGeneratedNameSet("Objects fields")
	for _, m := range g.program.Maps {
		if err := names.add(fmt.Sprintf("map %q", m.Name), exported(m.Name)); err != nil {
			return g.identifierError(err)
		}
	}
	for _, fn := range g.program.Functions {
		if err := names.add(fmt.Sprintf("program %q", fn.Name), exported(fn.Name)); err != nil {
			return g.identifierError(err)
		}
	}
	return nil
}

func (g *generator) validateObjectMethodNames() error {
	names := newGeneratedNameSet("Objects methods")
	names.reserve("generated Close method", "Close")
	for _, m := range g.program.Maps {
		if err := addMapMethodNames(names, m); err != nil {
			return g.identifierError(err)
		}
	}
	for _, fn := range g.program.Functions {
		if err := addAttachMethodNames(names, fn); err != nil {
			return g.identifierError(err)
		}
	}
	return nil
}

func (g *generator) validateStructFieldNames() error {
	for _, decl := range g.program.Structs {
		names := newGeneratedNameSet(fmt.Sprintf("struct %s fields", exported(decl.Name)))
		for _, field := range decl.Fields {
			if err := names.add(fmt.Sprintf("field %q", field.Name), exported(field.Name)); err != nil {
				return g.identifierError(err)
			}
		}
	}
	return nil
}

func (g *generator) identifierError(err error) error {
	return Error{Stage: "identifiers", Package: g.packageName, Err: err}
}

func addMapMethodNames(names *generatedNameSet, m ir.Map) error {
	field := exported(m.Name)
	if m.Kind == ir.MapKindRingbuf && m.Val.Name != "" {
		if err := names.add(fmt.Sprintf("ringbuf map %q reader", m.Name), "Read"+field); err != nil {
			return err
		}
	}
	if !isLookupMap(m) {
		return nil
	}
	for _, prefix := range []string{"Lookup", "Update", "ForEach"} {
		if err := names.add(fmt.Sprintf("map %q %s method", m.Name, prefix), prefix+field); err != nil {
			return err
		}
	}
	if m.Kind.IsHashLike() {
		return names.add(fmt.Sprintf("map %q Delete method", m.Name), "Delete"+field)
	}
	return nil
}

func addAttachMethodNames(names *generatedNameSet, fn ir.Function) error {
	if !emitsAttachMethod(fn) {
		return nil
	}
	field := exported(fn.Name)
	if err := names.add(fmt.Sprintf("program %q attach method", fn.Name), "Attach"+field); err != nil {
		return err
	}
	if fn.Section.Kind == ir.ProgramXDP || fn.Section.Kind == ir.ProgramTC {
		return names.add(fmt.Sprintf("program %q interface attach method", fn.Name), "Attach"+field+"Interface")
	}
	return nil
}

func emitsAttachMethod(fn ir.Function) bool {
	switch fn.Section.Kind {
	case ir.ProgramTracepoint:
		_, _, ok := strings.Cut(fn.Section.Attach, ":")
		return ok
	case ir.ProgramXDP, ir.ProgramTC, ir.ProgramCgroup, ir.ProgramLSM:
		return true
	case ir.ProgramKprobe, ir.ProgramKretprobe:
		return fn.Section.Attach != ""
	default:
		return false
	}
}

type generatedNameSet struct {
	scope string
	seen  map[string]string
}

func newGeneratedNameSet(scope string) *generatedNameSet {
	return &generatedNameSet{scope: scope, seen: map[string]string{}}
}

func (s *generatedNameSet) reserve(label string, generated string) {
	s.seen[generated] = label
}

func (s *generatedNameSet) add(label string, generated string) error {
	if !validGeneratedIdentifier(generated) {
		return fmt.Errorf("%s %s generates invalid Go identifier %q", s.scope, label, generated)
	}
	if prev, ok := s.seen[generated]; ok {
		return fmt.Errorf("%s %s and %s both generate Go identifier %q", s.scope, prev, label, generated)
	}
	s.seen[generated] = label
	return nil
}

func validGeneratedIdentifier(name string) bool {
	return token.IsIdentifier(name) && !token.Lookup(name).IsKeyword()
}

func (g *generator) emitPackage() {
	fmt.Fprintf(&g.b, "package %s\n\n", g.packageName)
	emitImports(&g.b, g.program)
}

func (g *generator) emitCapabilityManifest() error {
	data, err := json.MarshalIndent(capability.FromIR(g.program), "", "  ")
	if err != nil {
		return Error{Stage: "capability manifest", Package: g.packageName, Err: err}
	}
	data = append(data, '\n')
	fmt.Fprintf(&g.b, "const CapabilityManifestJSON = %s\n\n", strconv.Quote(string(data)))
	g.b.WriteString(`func CapabilityManifest() (capability.Manifest, error) {
	var manifest capability.Manifest
	if err := json.Unmarshal([]byte(CapabilityManifestJSON), &manifest); err != nil {
		return capability.Manifest{}, err
	}
	return manifest, nil
}

`)
	return nil
}

func (g *generator) emitTypes() {
	for _, decl := range g.program.Structs {
		emitStruct(&g.b, decl)
		emitStructLayoutAssertions(&g.b, decl, g.structs)
	}
}

func (g *generator) emitObjects() {
	g.b.WriteString("type Objects struct {\n")
	for _, m := range g.program.Maps {
		fmt.Fprintf(&g.b, "\t%s *ebpf.Map `ebpf:%q`\n", exported(m.Name), m.Name)
	}
	for _, fn := range g.program.Functions {
		fmt.Fprintf(&g.b, "\t%s *ebpf.Program `ebpf:%q`\n", exported(fn.Name), fn.Name)
	}
	g.b.WriteString("}\n\n")
}

func (g *generator) emitLoadHelpers() {
	g.b.WriteString(`type LoadOptions struct {
	Collection    *ebpf.CollectionOptions
	RemoveMemlock bool
}

func LoadObjects(path string) (*Objects, error) {
	return LoadObjectsWithOptions(path, LoadOptions{RemoveMemlock: true})
}

func LoadObjectsWithOptions(path string, opts LoadOptions) (*Objects, error) {
	if opts.RemoveMemlock {
		if err := rlimit.RemoveMemlock(); err != nil {
			return nil, fmt.Errorf("remove memlock limit: %w", err)
		}
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	var objects Objects
	if err := spec.LoadAndAssign(&objects, opts.Collection); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	return &objects, nil
}

`)
}

func (g *generator) emitClose() {
	g.b.WriteString(`func (o *Objects) Close() error {
	if o == nil {
		return nil
	}
	var err error
`)
	for _, m := range g.program.Maps {
		fmt.Fprintf(&g.b, "\tif o.%s != nil {\n\t\terr = errors.Join(err, o.%s.Close())\n\t}\n", exported(m.Name), exported(m.Name))
	}
	for _, fn := range g.program.Functions {
		fmt.Fprintf(&g.b, "\tif o.%s != nil {\n\t\terr = errors.Join(err, o.%s.Close())\n\t}\n", exported(fn.Name), exported(fn.Name))
	}
	g.b.WriteString("\treturn err\n}\n\n")
}

func (g *generator) emitMapHelpers() {
	for _, m := range g.program.Maps {
		if m.Kind == ir.MapKindRingbuf && m.Val.Name != "" {
			emitRingbufReader(&g.b, m)
		}
		if isLookupMap(m) {
			emitMapMethods(&g.b, m)
		}
	}
}

func (g *generator) emitAttachHelpers() {
	for _, fn := range g.program.Functions {
		emitAttach(&g.b, fn)
	}
}

func (g *generator) formatted() (string, error) {
	formatted, err := format.Source(g.b.Bytes())
	if err != nil {
		return "", Error{Stage: "format", Package: g.packageName, Err: err}
	}
	return string(formatted), nil
}

func validPackageName(name string) bool {
	return token.IsIdentifier(name) && !token.Lookup(name).IsKeyword()
}

func emitAttach(b *bytes.Buffer, fn ir.Function) {
	switch fn.Section.Kind {
	case ir.ProgramTracepoint:
		emitTracepointAttach(b, fn)
	case ir.ProgramXDP:
		emitXDPAttach(b, fn)
	case ir.ProgramTC:
		emitTCAttach(b, fn)
	case ir.ProgramCgroup:
		emitCgroupAttach(b, fn)
	case ir.ProgramLSM:
		emitLSMAttach(b, fn)
	case ir.ProgramKprobe:
		emitKprobeAttach(b, fn, "Kprobe")
	case ir.ProgramKretprobe:
		emitKprobeAttach(b, fn, "Kretprobe")
	}
}

func emitTracepointAttach(b *bytes.Buffer, fn ir.Function) {
	if fn.Section.Attach == "" {
		return
	}
	category, event, ok := strings.Cut(fn.Section.Attach, ":")
	if !ok {
		return
	}
	field := exported(fn.Name)
	fmt.Fprintf(b, `func (o *Objects) Attach%s() (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.Tracepoint(%q, %q, o.%s, nil)
}

`, field, field, fn.Name, category, event, field)
}

func emitXDPAttach(b *bytes.Buffer, fn ir.Function) {
	field := exported(fn.Name)
	fmt.Fprintf(b, `func (o *Objects) Attach%s(interfaceIndex int) (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.AttachXDP(link.XDPOptions{Program: o.%s, Interface: interfaceIndex})
}

func (o *Objects) Attach%sInterface(name string) (link.Link, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return o.Attach%s(iface.Index)
}

`, field, field, fn.Name, field, field, field)
}

func emitTCAttach(b *bytes.Buffer, fn ir.Function) {
	field := exported(fn.Name)
	attach := "ebpf.AttachTCXIngress"
	if fn.Section.Attach == "egress" {
		attach = "ebpf.AttachTCXEgress"
	}
	fmt.Fprintf(b, `func (o *Objects) Attach%s(interfaceIndex int) (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.AttachTCX(link.TCXOptions{Program: o.%s, Interface: interfaceIndex, Attach: %s})
}

func (o *Objects) Attach%sInterface(name string) (link.Link, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return o.Attach%s(iface.Index)
}

`, field, field, fn.Name, field, attach, field, field)
}

func emitCgroupAttach(b *bytes.Buffer, fn ir.Function) {
	field := exported(fn.Name)
	attach := "ebpf.AttachCGroupInet4Connect"
	if fn.Section.Attach == "connect6" {
		attach = "ebpf.AttachCGroupInet6Connect"
	}
	fmt.Fprintf(b, `func (o *Objects) Attach%s(cgroupPath string) (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: %s, Program: o.%s})
}

`, field, field, fn.Name, attach, field)
}

func emitLSMAttach(b *bytes.Buffer, fn ir.Function) {
	field := exported(fn.Name)
	fmt.Fprintf(b, `func (o *Objects) Attach%s() (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.AttachLSM(link.LSMOptions{Program: o.%s})
}

`, field, field, fn.Name, field)
}

func emitKprobeAttach(b *bytes.Buffer, fn ir.Function, linkFunc string) {
	if fn.Section.Attach == "" {
		return
	}
	field := exported(fn.Name)
	fmt.Fprintf(b, `func (o *Objects) Attach%s() (link.Link, error) {
	if o == nil || o.%s == nil {
		return nil, fmt.Errorf("%s program is not loaded")
	}
	return link.%s(%q, o.%s, nil)
}

`, field, field, fn.Name, linkFunc, fn.Section.Attach, field)
}

func emitImports(b *bytes.Buffer, program ir.Program) {
	needsRingbuf := hasRingbuf(program)
	needsAttach := hasAttach(program)
	needsInterfaceAttach := hasInterfaceAttach(program)
	std := []string{"encoding/json"}
	if needsRingbuf {
		std = append(std, "bytes", "context", "encoding/binary")
	}
	if len(program.Maps)+len(program.Functions) > 0 || needsRingbuf {
		std = append(std, "errors")
	}
	std = append(std, "fmt")
	if needsInterfaceAttach {
		std = append(std, "net")
	}
	if needsStructLayoutAssertions(program) {
		std = append(std, "unsafe")
	}
	thirdParty := []string{"github.com/cilium/ebpf", "m31labs.dev/horizon/capability"}
	if needsAttach {
		thirdParty = append(thirdParty, "github.com/cilium/ebpf/link")
	}
	if needsRingbuf {
		thirdParty = append(thirdParty, "github.com/cilium/ebpf/ringbuf")
	}
	thirdParty = append(thirdParty, "github.com/cilium/ebpf/rlimit")
	b.WriteString("import (\n")
	for _, path := range std {
		fmt.Fprintf(b, "\t%q\n", path)
	}
	if len(std) > 0 {
		b.WriteByte('\n')
	}
	for _, path := range thirdParty {
		fmt.Fprintf(b, "\t%q\n", path)
	}
	b.WriteString(")\n\n")
}

func isLookupMap(m ir.Map) bool {
	return m.Kind.IsLookup() && m.Key.Name != "" && m.Val.Name != ""
}

func hasRingbuf(program ir.Program) bool {
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf && m.Val.Name != "" {
			return true
		}
	}
	return false
}

func hasAttach(program ir.Program) bool {
	for _, fn := range program.Functions {
		switch fn.Section.Kind {
		case ir.ProgramTracepoint, ir.ProgramXDP, ir.ProgramTC, ir.ProgramCgroup, ir.ProgramLSM, ir.ProgramKprobe, ir.ProgramKretprobe:
			return true
		}
	}
	return false
}

func hasInterfaceAttach(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramXDP || fn.Section.Kind == ir.ProgramTC {
			return true
		}
	}
	return false
}

func needsStructLayoutAssertions(program ir.Program) bool {
	structs := ir.StructsByName(program.Structs)
	for _, decl := range program.Structs {
		if _, ok := ir.StructLayout(decl, structs); ok {
			return true
		}
	}
	return false
}

func emitStruct(b *bytes.Buffer, decl ir.Struct) {
	fmt.Fprintf(b, "type %s struct {\n", exported(decl.Name))
	for _, field := range decl.Fields {
		fmt.Fprintf(b, "\t%s %s\n", exported(field.Name), goType(field.Type))
	}
	b.WriteString("}\n\n")
}

func emitStructLayoutAssertions(b *bytes.Buffer, decl ir.Struct, structs map[string]ir.Struct) {
	layout, ok := ir.StructLayout(decl, structs)
	if !ok {
		return
	}
	typeName := exported(decl.Name)
	emitLayoutEqualityAssertion(b, fmt.Sprintf("unsafe.Sizeof(%s{})", typeName), layout.Size)
	for _, field := range layout.Fields {
		fieldName := exported(field.Name)
		emitLayoutEqualityAssertion(b, fmt.Sprintf("unsafe.Offsetof(%s{}.%s)", typeName, fieldName), field.Offset)
	}
	b.WriteString("\n")
}

func emitLayoutEqualityAssertion(b *bytes.Buffer, expr string, want int) {
	if want == 0 {
		fmt.Fprintf(b, "var _ [-int(%s)]byte\n", expr)
		return
	}
	fmt.Fprintf(b, "var _ [%d - int(%s)]byte\n", want, expr)
	fmt.Fprintf(b, "var _ [int(%s) - %d]byte\n", expr, want)
}

func emitRingbufReader(b *bytes.Buffer, m ir.Map) {
	mapField := exported(m.Name)
	eventType := exported(m.Val.Name)
	fmt.Fprintf(b, `func (o *Objects) Read%s(ctx context.Context, handle func(%s) error) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reader, err := ringbuf.NewReader(o.%s)
	if err != nil {
		return err
	}
	defer reader.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.Close()
		case <-done:
		}
	}()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var event %s
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return err
		}
		if err := handle(event); err != nil {
			return err
		}
	}
}

`, mapField, eventType, mapField, m.Name, mapField, eventType)
}

func emitMapMethods(b *bytes.Buffer, m ir.Map) {
	mapField := exported(m.Name)
	keyType := goType(m.Key)
	valueType := goType(m.Val)
	if m.Kind.HasPerCPUValue() {
		emitPerCPUMapMethods(b, m, mapField, keyType, valueType)
		return
	}
	fmt.Fprintf(b, `func (o *Objects) Lookup%s(key %s) (%s, bool, error) {
	var value %s
	if o == nil || o.%s == nil {
		return value, false, fmt.Errorf("%s map is not loaded")
	}
	if err := o.%s.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return value, false, nil
		}
		return value, false, err
	}
	return value, true, nil
}

func (o *Objects) Update%s(key %s, value %s) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	return o.%s.Update(key, value, ebpf.UpdateAny)
}

func (o *Objects) ForEach%s(handle func(key %s, value %s) error) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	iter := o.%s.Iterate()
	for {
		var key %s
		var value %s
		if !iter.Next(&key, &value) {
			break
		}
		if err := handle(key, value); err != nil {
			return err
		}
	}
	return iter.Err()
}

`, mapField, keyType, valueType, valueType, mapField, m.Name, mapField, mapField, keyType, valueType, mapField, m.Name, mapField, mapField, keyType, valueType, mapField, m.Name, mapField, keyType, valueType)
	if !m.Kind.IsHashLike() {
		return
	}
	emitDeleteMapMethod(b, m, mapField, keyType)
}

func emitPerCPUMapMethods(b *bytes.Buffer, m ir.Map, mapField string, keyType string, valueType string) {
	fmt.Fprintf(b, `func (o *Objects) Lookup%s(key %s) ([]%s, bool, error) {
	var values []%s
	if o == nil || o.%s == nil {
		return nil, false, fmt.Errorf("%s map is not loaded")
	}
	if err := o.%s.Lookup(key, &values); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return values, true, nil
}

func (o *Objects) Update%s(key %s, values []%s) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	return o.%s.Update(key, values, ebpf.UpdateAny)
}

func (o *Objects) ForEach%s(handle func(key %s, values []%s) error) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	iter := o.%s.Iterate()
	for {
		var key %s
		var values []%s
		if !iter.Next(&key, &values) {
			break
		}
		if err := handle(key, values); err != nil {
			return err
		}
	}
	return iter.Err()
}

`, mapField, keyType, valueType, valueType, mapField, m.Name, mapField, mapField, keyType, valueType, mapField, m.Name, mapField, mapField, keyType, valueType, mapField, m.Name, mapField, keyType, valueType)
	if !m.Kind.IsHashLike() {
		return
	}
	emitDeleteMapMethod(b, m, mapField, keyType)
}

func emitDeleteMapMethod(b *bytes.Buffer, m ir.Map, mapField string, keyType string) {
	fmt.Fprintf(b, `func (o *Objects) Delete%s(key %s) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	if err := o.%s.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	return nil
}

`, mapField, keyType, mapField, m.Name, mapField)
}

func goType(t ir.Type) string {
	if t.Len != "" && t.Elem != nil {
		return fmt.Sprintf("[%s]%s", t.Len, goType(*t.Elem))
	}
	switch t.Name {
	case "u8":
		return "uint8"
	case "u16":
		return "uint16"
	case "u32":
		return "uint32"
	case "u64":
		return "uint64"
	case "i8":
		return "int8"
	case "i16":
		return "int16"
	case "i32":
		return "int32"
	case "i64":
		return "int64"
	case "bool":
		return "bool"
	default:
		return exported(t.Name)
	}
}

func exported(name string) string {
	if name == "" {
		return name
	}
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	for i, part := range parts {
		runes := []rune(part)
		if len(runes) == 0 {
			continue
		}
		runes[0] = unicode.ToUpper(runes[0])
		parts[i] = string(runes)
	}
	return strings.Join(parts, "")
}
