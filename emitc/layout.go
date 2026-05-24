package emitc

import (
	"strconv"

	"m31labs.dev/horizon/ir"
)

type cLayout struct {
	Size   int
	Align  int
	Fields []cFieldLayout
}

type cFieldLayout struct {
	Name   string
	Offset int
}

func cStructMap(program ir.Program) map[string]ir.Struct {
	structs := make(map[string]ir.Struct, len(program.Structs))
	for _, decl := range program.Structs {
		structs[decl.Name] = decl
	}
	return structs
}

func cStructLayout(decl ir.Struct, structs map[string]ir.Struct) (cLayout, bool) {
	return cStructLayoutSeen(decl, structs, map[string]bool{})
}

func cStructLayoutSeen(decl ir.Struct, structs map[string]ir.Struct, seen map[string]bool) (cLayout, bool) {
	if decl.Name != "" {
		if seen[decl.Name] {
			return cLayout{}, false
		}
		seen[decl.Name] = true
		defer delete(seen, decl.Name)
	}

	layout := cLayout{Align: 1, Fields: make([]cFieldLayout, 0, len(decl.Fields))}
	offset := 0
	for _, field := range decl.Fields {
		fieldLayout, ok := cTypeLayout(field.Type, structs, seen)
		if !ok {
			return cLayout{}, false
		}
		offset = alignUp(offset, fieldLayout.Align)
		layout.Fields = append(layout.Fields, cFieldLayout{Name: field.Name, Offset: offset})
		offset += fieldLayout.Size
		if fieldLayout.Align > layout.Align {
			layout.Align = fieldLayout.Align
		}
	}
	layout.Size = alignUp(offset, layout.Align)
	return layout, true
}

func cTypeLayout(typ ir.Type, structs map[string]ir.Struct, seen map[string]bool) (cLayout, bool) {
	if typ.Ptr {
		return cLayout{Size: 8, Align: 8}, true
	}
	if typ.Len != "" && typ.Elem != nil {
		length, err := strconv.Atoi(typ.Len)
		if err != nil || length <= 0 {
			return cLayout{}, false
		}
		elem, ok := cTypeLayout(*typ.Elem, structs, seen)
		if !ok {
			return cLayout{}, false
		}
		return cLayout{Size: elem.Size * length, Align: elem.Align}, true
	}
	if size, ok := cScalarSize(typ.Name); ok {
		return cLayout{Size: size, Align: size}, true
	}
	if decl, ok := structs[typ.Name]; ok {
		return cStructLayoutSeen(decl, structs, seen)
	}
	return cLayout{}, false
}

func cScalarSize(name string) (int, bool) {
	switch name {
	case "u8", "i8", "bool":
		return 1, true
	case "u16", "i16":
		return 2, true
	case "u32", "i32":
		return 4, true
	case "u64", "i64", "untyped_int":
		return 8, true
	default:
		return 0, false
	}
}

func alignUp(value int, align int) int {
	if align <= 1 {
		return value
	}
	remainder := value % align
	if remainder == 0 {
		return value
	}
	return value + align - remainder
}
