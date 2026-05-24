package ir

import "testing"

func TestStructLayoutIncludesPaddingAndOffsets(t *testing.T) {
	layout, ok := StructLayout(Struct{
		Name: "LayoutEvent",
		Fields: []Field{{
			Name: "tag",
			Type: Type{Name: "u8"},
		}, {
			Name: "pid",
			Type: Type{Name: "u32"},
		}, {
			Name: "ports",
			Type: Type{Len: "3", Elem: &Type{Name: "u16"}},
		}},
	}, nil)
	if !ok {
		t.Fatal("StructLayout returned false")
	}
	if layout.Size != 16 || layout.Align != 4 {
		t.Fatalf("layout = %#v, want size 16 align 4", layout)
	}
	wantOffsets := map[string]int{"tag": 0, "pid": 4, "ports": 8}
	for _, field := range layout.Fields {
		if wantOffsets[field.Name] != field.Offset {
			t.Fatalf("field %s offset = %d, want %d", field.Name, field.Offset, wantOffsets[field.Name])
		}
	}
}

func TestStructLayoutRejectsUnknownFieldType(t *testing.T) {
	_, ok := StructLayout(Struct{
		Name: "Bad",
		Fields: []Field{{
			Name: "value",
			Type: Type{Name: "Missing"},
		}},
	}, nil)
	if ok {
		t.Fatal("StructLayout returned true for unknown field type")
	}
}
