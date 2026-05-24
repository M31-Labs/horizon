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
