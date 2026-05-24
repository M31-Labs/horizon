package bindgen

import (
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
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
		`"github.com/cilium/ebpf/rlimit"`,
		"type LoadOptions struct",
		"return LoadObjectsWithOptions(path, LoadOptions{RemoveMemlock: true})",
		"if err := rlimit.RemoveMemlock(); err != nil",
		"if err := spec.LoadAndAssign(&objects, opts.Collection); err != nil",
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
		`"unsafe"`,
	} {
		if strings.Contains(code, unwanted) {
			t.Fatalf("generated bindings unexpectedly contain %q:\n%s", unwanted, code)
		}
	}
}

func TestGenerateRejectsInvalidPackageName(t *testing.T) {
	code, err := Generate(ir.Program{}, "bad-name")
	if err == nil {
		t.Fatalf("Generate succeeded, code:\n%s", code)
	}
	if code != "" {
		t.Fatalf("Generate returned code for invalid package:\n%s", code)
	}
	d, ok := DiagnosticForError(err)
	if !ok {
		t.Fatalf("DiagnosticForError(%T) = false", err)
	}
	if d.Code != "HZN3200" || d.Severity != diag.SeverityError {
		t.Fatalf("diagnostic = %#v, want HZN3200 error", d)
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

func TestGenerateTCAttachBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "PassIngress",
			Section: ir.Section{
				Kind:   ir.ProgramTC,
				Attach: "ingress",
				Name:   "tc/ingress",
			},
		}, {
			Name: "PassEgress",
			Section: ir.Section{
				Kind:   ir.ProgramTC,
				Attach: "egress",
				Name:   "tc/egress",
			},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"net"`,
		`"github.com/cilium/ebpf/link"`,
		"func (o *Objects) AttachPassIngress(interfaceIndex int) (link.Link, error)",
		"func (o *Objects) AttachPassIngressInterface(name string) (link.Link, error)",
		"return link.AttachTCX(link.TCXOptions{Program: o.PassIngress, Interface: interfaceIndex, Attach: ebpf.AttachTCXIngress})",
		"func (o *Objects) AttachPassEgress(interfaceIndex int) (link.Link, error)",
		"return link.AttachTCX(link.TCXOptions{Program: o.PassEgress, Interface: interfaceIndex, Attach: ebpf.AttachTCXEgress})",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
}

func TestGenerateCgroupAttachBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "BlockConnect4",
			Section: ir.Section{
				Kind:   ir.ProgramCgroup,
				Attach: "connect4",
				Name:   "cgroup/connect4",
			},
		}, {
			Name: "BlockConnect6",
			Section: ir.Section{
				Kind:   ir.ProgramCgroup,
				Attach: "connect6",
				Name:   "cgroup/connect6",
			},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"github.com/cilium/ebpf/link"`,
		"func (o *Objects) AttachBlockConnect4(cgroupPath string) (link.Link, error)",
		"return link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: ebpf.AttachCGroupInet4Connect, Program: o.BlockConnect4})",
		"func (o *Objects) AttachBlockConnect6(cgroupPath string) (link.Link, error)",
		"return link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: ebpf.AttachCGroupInet6Connect, Program: o.BlockConnect6})",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, `"net"`) {
		t.Fatalf("generated cgroup bindings unexpectedly import net:\n%s", code)
	}
}

func TestGenerateLSMAttachBindings(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Functions: []ir.Function{{
			Name: "DenyFileOpen",
			Section: ir.Section{
				Kind:   ir.ProgramLSM,
				Attach: "file_open",
				Name:   "lsm/file_open",
			},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"github.com/cilium/ebpf/link"`,
		"func (o *Objects) AttachDenyFileOpen() (link.Link, error)",
		"return link.AttachLSM(link.LSMOptions{Program: o.DenyFileOpen})",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, `"net"`) {
		t.Fatalf("generated LSM bindings unexpectedly import net:\n%s", code)
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
		`"unsafe"`,
		`"github.com/cilium/ebpf"`,
		"var _ [4 - int(unsafe.Sizeof(Count{}))]byte",
		"var _ [-int(unsafe.Offsetof(Count{}.Seen))]byte",
		"func (o *Objects) LookupCounts(key uint32) (Count, bool, error)",
		"if errors.Is(err, ebpf.ErrKeyNotExist)",
		"func (o *Objects) UpdateCounts(key uint32, value Count) error",
		"return o.Counts.Update(key, value, ebpf.UpdateAny)",
		"func (o *Objects) ForEachCounts(handle func(key uint32, value Count) error) error",
		"iter := o.Counts.Iterate()",
		"return iter.Err()",
		"func (o *Objects) DeleteCounts(key uint32) error",
		"func (o *Objects) LookupSlots(key uint32) (uint64, bool, error)",
		"func (o *Objects) UpdateSlots(key uint32, value uint64) error",
		"func (o *Objects) ForEachSlots(handle func(key uint32, value uint64) error) error",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, "DeleteSlots") {
		t.Fatalf("generated array bindings unexpectedly include delete:\n%s", code)
	}
}

func TestGenerateStructLayoutAssertionsIncludePadding(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Structs: []ir.Struct{{
			Name: "LayoutEvent",
			Fields: []ir.Field{{
				Name: "tag",
				Type: ir.Type{Name: "u8"},
			}, {
				Name: "pid",
				Type: ir.Type{Name: "u32"},
			}, {
				Name: "ports",
				Type: ir.Type{Len: "3", Elem: &ir.Type{Name: "u16"}},
			}},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"unsafe"`,
		"var _ [16 - int(unsafe.Sizeof(LayoutEvent{}))]byte",
		"var _ [-int(unsafe.Offsetof(LayoutEvent{}.Tag))]byte",
		"var _ [4 - int(unsafe.Offsetof(LayoutEvent{}.Pid))]byte",
		"var _ [8 - int(unsafe.Offsetof(LayoutEvent{}.Ports))]byte",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
}

func TestGenerateRingbufReaderObservesContext(t *testing.T) {
	code, err := Generate(ir.Program{
		Package: "probes",
		Structs: []ir.Struct{{
			Name: "ExecEvent",
			Fields: []ir.Field{{
				Name: "pid",
				Type: ir.Type{Name: "u32"},
			}},
		}},
		Maps: []ir.Map{{
			Name: "ExecEvents",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "ExecEvent"},
		}},
	}, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		"func (o *Objects) ReadExecEvents(ctx context.Context, handle func(ExecEvent) error) error",
		"if ctx == nil {",
		"ctx = context.Background()",
		"done := make(chan struct{})",
		"defer close(done)",
		"go func() {",
		"case <-ctx.Done():",
		"_ = reader.Close()",
		"case <-done:",
		"if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {",
		"return ctx.Err()",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("generated bindings missing %q:\n%s", want, code)
		}
	}
}
