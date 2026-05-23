package bindings

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ExecEvent struct {
	Pid  uint32
	Ppid uint32
	Uid  uint32
	Comm [16]uint8
}

type Objects struct {
	ExecEvents *ebpf.Map     `ebpf:"ExecEvents"`
	OnExec     *ebpf.Program `ebpf:"OnExec"`
}

func LoadObjects(path string) (*Objects, error) {
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
	reader, err := ringbuf.NewReader(o.ExecEvents)
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
