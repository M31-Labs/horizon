package ir

import "strconv"

type TypeLayout struct {
	Size   int
	Align  int
	Fields []FieldLayout
}

type FieldLayout struct {
	Name   string
	Offset int
}

func StructsByName(structs []Struct) map[string]Struct {
	out := make(map[string]Struct, len(structs))
	for _, decl := range structs {
		out[decl.Name] = decl
	}
	return out
}

func StructLayout(decl Struct, structs map[string]Struct) (TypeLayout, bool) {
	return structLayoutSeen(decl, structs, map[string]bool{})
}

func TypeLayoutOf(typ Type, structs map[string]Struct) (TypeLayout, bool) {
	return typeLayoutSeen(typ, structs, map[string]bool{})
}

func structLayoutSeen(decl Struct, structs map[string]Struct, seen map[string]bool) (TypeLayout, bool) {
	if decl.Name != "" {
		if seen[decl.Name] {
			return TypeLayout{}, false
		}
		seen[decl.Name] = true
		defer delete(seen, decl.Name)
	}

	layout := TypeLayout{Align: 1, Fields: make([]FieldLayout, 0, len(decl.Fields))}
	offset := 0
	for _, field := range decl.Fields {
		fieldLayout, ok := typeLayoutSeen(field.Type, structs, seen)
		if !ok {
			return TypeLayout{}, false
		}
		offset = alignUp(offset, fieldLayout.Align)
		layout.Fields = append(layout.Fields, FieldLayout{Name: field.Name, Offset: offset})
		offset += fieldLayout.Size
		if fieldLayout.Align > layout.Align {
			layout.Align = fieldLayout.Align
		}
	}
	layout.Size = alignUp(offset, layout.Align)
	return layout, true
}

func typeLayoutSeen(typ Type, structs map[string]Struct, seen map[string]bool) (TypeLayout, bool) {
	if typ.Ptr {
		return TypeLayout{Size: 8, Align: 8}, true
	}
	if typ.Len != "" && typ.Elem != nil {
		length, err := strconv.Atoi(typ.Len)
		if err != nil || length <= 0 {
			return TypeLayout{}, false
		}
		elem, ok := typeLayoutSeen(*typ.Elem, structs, seen)
		if !ok {
			return TypeLayout{}, false
		}
		return TypeLayout{Size: elem.Size * length, Align: elem.Align}, true
	}
	if size, ok := scalarSize(typ.Name); ok {
		return TypeLayout{Size: size, Align: size}, true
	}
	if decl, ok := structs[typ.Name]; ok {
		return structLayoutSeen(decl, structs, seen)
	}
	return TypeLayout{}, false
}

func scalarSize(name string) (int, bool) {
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
