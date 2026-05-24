package bindgen

import (
	"strings"
	"testing"

	"m31labs.dev/horizon/ir"
)

func TestGenerateXDPAttachBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "DropAll",
			Section: ir.Section{
				Kind: ir.ProgramXDP,
				Name: "xdp",
			},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"net"`,
		`"github.com/cilium/ebpf/link"`,
		"func (o *Objects) AttachDropAll(interfaceIndex int) (link.Link, error)",
		"func (o *Objects) AttachDropAllInterface(name string) (link.Link, error)",
		"return link.AttachXDP(link.XDPOptions{Program: o.DropAll, Interface: interfaceIndex})",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	for _, unwanted := range []string{
		`"github.com/cilium/ebpf/ringbuf"`,
		`"encoding/binary"`,
	} {
		if strings.Contains(code, unwanted) {
			t.Fatalf("generated bindings unexpectedly contain %q:\n%s", unwanted, code)
		}
	}
}

func TestGenerateKprobeAttachBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "OnOpen",
			Section: ir.Section{
				Kind:   ir.ProgramKprobe,
				Attach: "do_sys_openat2",
				Name:   "kprobe/do_sys_openat2",
			},
		}, {
			Name: "OnOpenReturn",
			Section: ir.Section{
				Kind:   ir.ProgramKretprobe,
				Attach: "do_sys_openat2",
				Name:   "kretprobe/do_sys_openat2",
			},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"github.com/cilium/ebpf/link"`,
		"func (o *Objects) AttachOnOpen() (link.Link, error)",
		`return link.Kprobe("do_sys_openat2", o.OnOpen, nil)`,
		"func (o *Objects) AttachOnOpenReturn() (link.Link, error)",
		`return link.Kretprobe("do_sys_openat2", o.OnOpenReturn, nil)`,
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, `"net"`) {
		t.Fatalf("generated kprobe bindings unexpectedly import net:\n%s", code)
	}
}

func TestGenerateTypedMapBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Structs: []ir.Struct{{
			Name: "Count",
			Fields: []ir.Field{{
				Name: "seen",
				Type: ir.Type{Name: "u32"},
			}},
		}},
		Maps: []ir.Map{{
			Name: "Counts",
			Kind: ir.MapKindHash,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "Count"},
		}, {
			Name: "Slots",
			Kind: ir.MapKindArray,
			Key:  ir.Type{Name: "u32"},
			Val:  ir.Type{Name: "u64"},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"errors"`,
		`"fmt"`,
		`"github.com/cilium/ebpf"`,
		"func (o *Objects) LookupCounts(key uint32) (Count, bool, error)",
		"if errors.Is(err, ebpf.ErrKeyNotExist)",
		"func (o *Objects) UpdateCounts(key uint32, value Count) error",
		"return o.Counts.Update(key, value, ebpf.UpdateAny)",
		"func (o *Objects) DeleteCounts(key uint32) error",
		"func (o *Objects) LookupSlots(key uint32) (uint64, bool, error)",
		"func (o *Objects) UpdateSlots(key uint32, value uint64) error",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, "DeleteSlots") {
		t.Fatalf("generated array bindings unexpectedly include delete:\n%s", code)
	}
}
