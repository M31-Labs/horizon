package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type openEvent struct {
	Pid  uint32
	Uid  uint32
	Comm [16]uint8
	Path [256]uint8
}

type objects struct {
	OpenEvents *ebpf.Map     `ebpf:"OpenEvents"`
	OnOpen     *ebpf.Program `ebpf:"OnOpen"`
}

func main() {
	objPath := flag.String("obj", "dist/open.bpf.o", "compiled Horizon eBPF object")
	timeout := flag.Duration("timeout", 0, "optional run duration")
	flag.Parse()

	if err := run(*objPath, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(objPath string, timeout time.Duration) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}
	var objs objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer closeObjects(&objs)

	kp, err := link.Kprobe("do_sys_openat2", objs.OnOpen, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe do_sys_openat2: %w", err)
	}
	defer kp.Close()

	reader, err := ringbuf.NewReader(objs.OpenEvents)
	if err != nil {
		return fmt.Errorf("open OpenEvents ringbuf: %w", err)
	}
	defer reader.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	fmt.Println("PID\tUID\tCOMM\tPATH")
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read OpenEvents: %w", err)
		}
		var event openEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode OpenEvent: %w", err)
		}
		fmt.Printf("%d\t%d\t%s\t%s\n", event.Pid, event.Uid, byteString(event.Comm[:]), byteString(event.Path[:]))
	}
}

func closeObjects(objs *objects) {
	if objs == nil {
		return
	}
	if objs.OpenEvents != nil {
		_ = objs.OpenEvents.Close()
	}
	if objs.OnOpen != nil {
		_ = objs.OnOpen.Close()
	}
}

func byteString(value []uint8) string {
	n := bytes.IndexByte(value, 0)
	if n < 0 {
		n = len(value)
	}
	return strings.TrimSpace(string(value[:n]))
}
