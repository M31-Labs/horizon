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

type tcpConnectEvent struct {
	Pid  uint32
	Uid  uint32
	Comm [16]uint8
}

type objects struct {
	TCPConnectEvents *ebpf.Map     `ebpf:"TCPConnectEvents"`
	OnTCPConnect     *ebpf.Program `ebpf:"OnTCPConnect"`
}

func main() {
	objPath := flag.String("obj", "dist/tcp.bpf.o", "compiled Horizon eBPF object")
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

	kp, err := link.Kprobe("tcp_v4_connect", objs.OnTCPConnect, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe tcp_v4_connect: %w", err)
	}
	defer kp.Close()

	reader, err := ringbuf.NewReader(objs.TCPConnectEvents)
	if err != nil {
		return fmt.Errorf("open TCPConnectEvents ringbuf: %w", err)
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

	fmt.Println("PID\tUID\tCOMM")
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read TCPConnectEvents: %w", err)
		}
		var event tcpConnectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode TCPConnectEvent: %w", err)
		}
		fmt.Printf("%d\t%d\t%s\n", event.Pid, event.Uid, commString(event.Comm))
	}
}

func closeObjects(objs *objects) {
	if objs == nil {
		return
	}
	if objs.TCPConnectEvents != nil {
		_ = objs.TCPConnectEvents.Close()
	}
	if objs.OnTCPConnect != nil {
		_ = objs.OnTCPConnect.Close()
	}
}

func commString(comm [16]uint8) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = len(comm)
	}
	return strings.TrimSpace(string(comm[:n]))
}
