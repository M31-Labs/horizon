package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type objects struct {
	ObserveTaskKill *ebpf.Program `ebpf:"ObserveTaskKill"`
}

func main() {
	objPath := flag.String("obj", "dist/kill.bpf.o", "compiled Horizon eBPF object")
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
	defer func() {
		if objs.ObserveTaskKill != nil {
			_ = objs.ObserveTaskKill.Close()
		}
	}()

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.ObserveTaskKill})
	if err != nil {
		return fmt.Errorf("attach LSM task_kill: %w", err)
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	fmt.Println("LSM task_kill observer attached; press Ctrl-C to detach")
	<-ctx.Done()
	return nil
}
