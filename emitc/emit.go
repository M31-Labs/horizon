package emitc

import (
	"fmt"
	"regexp"
	"strings"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func Emit(program ir.Program) (Output, error) {
	var b strings.Builder
	b.WriteString("#include \"vmlinux.h\"\n")
	b.WriteString("#include <bpf/bpf_helpers.h>\n\n")
	b.WriteString("#include <bpf/bpf_tracing.h>\n\n")
	b.WriteString("char LICENSE[] SEC(\"license\") = \"GPL\";\n")
	for _, decl := range program.Structs {
		emitStruct(&b, decl)
	}
	for _, m := range program.Maps {
		emitMap(&b, m)
	}
	var sourceMap ir.SourceMap
	for _, fn := range program.Functions {
		startLine := strings.Count(b.String(), "\n") + 1
		fmt.Fprintf(&b, "\nSEC(%q)\nint %s(%s) {\n", fn.Section.Name, fn.Name, cContext(fn))
		depth := 1
		for _, line := range cBodyLines(fn.BodyText) {
			if line == "}" && depth > 1 {
				depth--
			}
			opened := emitLine(&b, line, program.Maps, depth)
			if opened {
				depth++
			}
		}
		b.WriteString("}\n")
		sourceMap.Mappings = append(sourceMap.Mappings, ir.SourceMapping{
			Source:   fn.Span,
			Function: fn.Name,
			Section:  fn.Section.Name,
			Node:     "function",
			Generated: span.Span{
				Start: span.Point{Line: startLine, Column: 1},
				End:   span.Point{Line: strings.Count(b.String(), "\n") + 1, Column: 1},
			},
		})
	}
	return Output{Code: b.String(), SourceMap: sourceMap}, nil
}

func emitStruct(b *strings.Builder, decl ir.Struct) {
	fmt.Fprintf(b, "\nstruct %s {\n", decl.Name)
	for _, field := range decl.Fields {
		if field.Type.Len != "" && field.Type.Elem != nil {
			fmt.Fprintf(b, "    %s %s[%s];\n", cType(*field.Type.Elem), field.Name, field.Type.Len)
			continue
		}
		fmt.Fprintf(b, "    %s %s;\n", cType(field.Type), field.Name)
	}
	b.WriteString("};\n")
}

func emitMap(b *strings.Builder, m ir.Map) {
	switch m.Kind {
	case ir.MapKindRingbuf:
		fmt.Fprintf(b, `
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} %s SEC(".maps");
`, m.Name)
	}
}

func cType(t ir.Type) string {
	if t.Ptr && t.Elem != nil {
		return cType(*t.Elem) + " *"
	}
	switch t.Name {
	case "u8":
		return "__u8"
	case "u16":
		return "__u16"
	case "u32":
		return "__u32"
	case "u64":
		return "__u64"
	case "i8":
		return "__s8"
	case "i16":
		return "__s16"
	case "i32":
		return "__s32"
	case "i64":
		return "__s64"
	case "bool":
		return "bool"
	default:
		if t.Name != "" {
			return "struct " + t.Name
		}
		return "void"
	}
}

func cContext(fn ir.Function) string {
	if fn.Section.Kind != ir.ProgramTracepoint || fn.Section.Attach == "" {
		return "void *ctx"
	}
	event := fn.Section.Attach
	if idx := strings.IndexByte(event, ':'); idx >= 0 {
		event = event[idx+1:]
	}
	return "struct trace_event_raw_" + cIdent(event) + " *ctx"
}

var nonIdentRE = regexp.MustCompile(`[^A-Za-z0-9_]`)

func cIdent(s string) string {
	return nonIdentRE.ReplaceAllString(s, "_")
}

func cBodyLines(body string) []string {
	body = strings.ReplaceAll(body, "{", "{\n")
	body = strings.ReplaceAll(body, "}", "\n}\n")
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, strings.TrimSuffix(line, ";"))
	}
	return out
}

var (
	reserveLineRE     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*([A-Za-z_][A-Za-z0-9_]*)\.reserve\(\)$`)
	consumeLineRE     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.(submit|discard)\(([A-Za-z_][A-Za-z0-9_]*)\)$`)
	currentCommLineRE = regexp.MustCompile(`^bpf\.current_comm\(&([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\)$`)
	assignLineRE      = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	returnLineRE      = regexp.MustCompile(`^return\s+(.+)$`)
	ifLineRE          = regexp.MustCompile(`^if\s+(.+)\s+\{$`)
)

func emitLine(b *strings.Builder, line string, maps []ir.Map, depth int) bool {
	indent := strings.Repeat("    ", depth)
	switch {
	case line == "}":
		fmt.Fprintf(b, "%s}\n", indent)
	case ifLineRE.MatchString(line):
		cond := ifLineRE.FindStringSubmatch(line)[1]
		cond = strings.ReplaceAll(cond, "nil", "0")
		fmt.Fprintf(b, "%sif (%s) {\n", indent, cond)
		return true
	case reserveLineRE.MatchString(line):
		match := reserveLineRE.FindStringSubmatch(line)
		varName, mapName := match[1], match[2]
		fmt.Fprintf(b, "%s%s *%s = bpf_ringbuf_reserve(&%s, sizeof(*%s), 0);\n", indent, reserveType(mapName, maps), varName, mapName, varName)
	case consumeLineRE.MatchString(line):
		match := consumeLineRE.FindStringSubmatch(line)
		op, varName := match[2], match[3]
		if op == "discard" {
			fmt.Fprintf(b, "%sbpf_ringbuf_discard(%s, 0);\n", indent, varName)
		} else {
			fmt.Fprintf(b, "%sbpf_ringbuf_submit(%s, 0);\n", indent, varName)
		}
	case currentCommLineRE.MatchString(line):
		match := currentCommLineRE.FindStringSubmatch(line)
		fmt.Fprintf(b, "%sbpf_get_current_comm(%s->%s, sizeof(%s->%s));\n", indent, match[1], match[2], match[1], match[2])
	case assignLineRE.MatchString(line):
		match := assignLineRE.FindStringSubmatch(line)
		fmt.Fprintf(b, "%s%s->%s = %s;\n", indent, match[1], match[2], cExpr(match[3]))
	case returnLineRE.MatchString(line):
		match := returnLineRE.FindStringSubmatch(line)
		fmt.Fprintf(b, "%sreturn %s;\n", indent, cExpr(match[1]))
	default:
		fmt.Fprintf(b, "%s%s;\n", indent, cExpr(line))
	}
	return false
}

func reserveType(mapName string, maps []ir.Map) string {
	for _, m := range maps {
		if m.Name == mapName && m.Val.Name != "" {
			return "struct " + m.Val.Name
		}
	}
	return "void"
}

func cExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "bpf.current_pid()":
		return "(__u32)(bpf_get_current_pid_tgid() >> 32)"
	case "bpf.current_ppid()":
		return "0"
	case "bpf.current_uid()":
		return "(__u32)bpf_get_current_uid_gid()"
	case "nil":
		return "0"
	default:
		return strings.ReplaceAll(expr, "nil", "0")
	}
}
