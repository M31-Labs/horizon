package bindgen

import (
	"bytes"
	"fmt"
	"go/format"
	"strings"
	"unicode"

	"m31labs.dev/horizon/ir"
)

func Generate(program ir.Program, packageName string) (string, error) {
	if packageName == "" {
		packageName = "bindings"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n\n", packageName)
	emitImports(&b, program)
	for _, decl := range program.Structs {
		emitStruct(&b, decl)
	}
	b.WriteString("type Objects struct {\n")
	for _, m := range program.Maps {
		fmt.Fprintf(&b, "\t%s *ebpf.Map `ebpf:%q`\n", exported(m.Name), m.Name)
	}
	for _, fn := range program.Functions {
		fmt.Fprintf(&b, "\t%s *ebpf.Program `ebpf:%q`\n", exported(fn.Name), fn.Name)
	}
	b.WriteString("}\n\n")
	b.WriteString(`func LoadObjects(path string) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	var objects Objects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, err
	}
	return &objects, nil
}

func (o *Objects) Close() error {
	if o == nil {
		return nil
	}
	var err error
`)
	for _, m := range program.Maps {
		fmt.Fprintf(&b, "\tif o.%s != nil {\n\t\terr = errors.Join(err, o.%s.Close())\n\t}\n", exported(m.Name), exported(m.Name))
	}
	for _, fn := range program.Functions {
		fmt.Fprintf(&b, "\tif o.%s != nil {\n\t\terr = errors.Join(err, o.%s.Close())\n\t}\n", exported(fn.Name), exported(fn.Name))
	}
	b.WriteString("\treturn err\n}\n\n")
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf && m.Val.Name != "" {
			emitRingbufReader(&b, m)
		}
	}
	for _, fn := range program.Functions {
		emitAttach(&b, fn)
	}
	formatted, err := format.Source(b.Bytes())
	if err != nil {
		return b.String(), nil
	}
	return string(formatted), nil
}

func emitAttach(b *bytes.Buffer, fn ir.Function) {
	switch fn.Section.Kind {
	case ir.ProgramTracepoint:
		emitTracepointAttach(b, fn)
	case ir.ProgramXDP:
		emitXDPAttach(b, fn)
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
	needsXDP := hasXDP(program)
	var std []string
	if needsRingbuf {
		std = append(std, "bytes", "context", "encoding/binary")
	}
	if len(program.Maps)+len(program.Functions) > 0 || needsRingbuf {
		std = append(std, "errors")
	}
	if needsRingbuf || needsAttach {
		std = append(std, "fmt")
	}
	if needsXDP {
		std = append(std, "net")
	}
	thirdParty := []string{"github.com/cilium/ebpf"}
	if needsAttach {
		thirdParty = append(thirdParty, "github.com/cilium/ebpf/link")
	}
	if needsRingbuf {
		thirdParty = append(thirdParty, "github.com/cilium/ebpf/ringbuf")
	}
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
		case ir.ProgramTracepoint, ir.ProgramXDP, ir.ProgramKprobe, ir.ProgramKretprobe:
			return true
		}
	}
	return false
}

func hasXDP(program ir.Program) bool {
	for _, fn := range program.Functions {
		if fn.Section.Kind == ir.ProgramXDP {
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

func emitRingbufReader(b *bytes.Buffer, m ir.Map) {
	mapField := exported(m.Name)
	eventType := exported(m.Val.Name)
	fmt.Fprintf(b, `func (o *Objects) Read%s(ctx context.Context, handle func(%s) error) error {
	if o == nil || o.%s == nil {
		return fmt.Errorf("%s map is not loaded")
	}
	reader, err := ringbuf.NewReader(o.%s)
	if err != nil {
		return err
	}
	defer reader.Close()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(ctx.Err(), context.Canceled) {
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
