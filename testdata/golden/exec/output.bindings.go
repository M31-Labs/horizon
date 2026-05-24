package bindings

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ExecEvent struct {
	TsNs uint64
	Pid  uint32
	Ppid uint32
	Uid  uint32
	Comm [16]uint8
}

var _ [40 - int(unsafe.Sizeof(ExecEvent{}))]byte
var _ [int(unsafe.Sizeof(ExecEvent{})) - 40]byte
var _ [-int(unsafe.Offsetof(ExecEvent{}.TsNs))]byte
var _ [8 - int(unsafe.Offsetof(ExecEvent{}.Pid))]byte
var _ [int(unsafe.Offsetof(ExecEvent{}.Pid)) - 8]byte
var _ [12 - int(unsafe.Offsetof(ExecEvent{}.Ppid))]byte
var _ [int(unsafe.Offsetof(ExecEvent{}.Ppid)) - 12]byte
var _ [16 - int(unsafe.Offsetof(ExecEvent{}.Uid))]byte
var _ [int(unsafe.Offsetof(ExecEvent{}.Uid)) - 16]byte
var _ [20 - int(unsafe.Offsetof(ExecEvent{}.Comm))]byte
var _ [int(unsafe.Offsetof(ExecEvent{}.Comm)) - 20]byte

type Objects struct {
	ExecEvents *ebpf.Map     `ebpf:"ExecEvents"`
	OnExec     *ebpf.Program `ebpf:"OnExec"`
}

type LoadOptions struct {
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

func (o *Objects) Close() error {
	if o == nil {
		return nil
	}
	var err error
	if o.ExecEvents != nil {
		err = errors.Join(err, o.ExecEvents.Close())
	}
	if o.OnExec != nil {
		err = errors.Join(err, o.OnExec.Close())
	}
	return err
}

func (o *Objects) ReadExecEvents(ctx context.Context, handle func(ExecEvent) error) error {
	if o == nil || o.ExecEvents == nil {
		return fmt.Errorf("ExecEvents map is not loaded")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reader, err := ringbuf.NewReader(o.ExecEvents)
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
		var event ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return err
		}
		if err := handle(event); err != nil {
			return err
		}
	}
}

func (o *Objects) AttachOnExec() (link.Link, error) {
	if o == nil || o.OnExec == nil {
		return nil, fmt.Errorf("OnExec program is not loaded")
	}
	return link.Tracepoint("sched", "sched_process_exec", o.OnExec, nil)
}
