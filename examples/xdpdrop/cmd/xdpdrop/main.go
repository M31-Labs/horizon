package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type objects struct {
	DropTCP *ebpf.Program `ebpf:"DropTCP"`
}

func main() {
	objPath := flag.String("obj", "dist/xdp.bpf.o", "compiled Horizon eBPF object")
	ifaceName := flag.String("iface", "", "network interface to attach the XDP program to")
	timeout := flag.Duration("timeout", 0, "optional run duration")
	flag.Parse()

	if err := run(*objPath, *ifaceName, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(objPath string, ifaceName string, timeout time.Duration) error {
	if ifaceName == "" {
		return fmt.Errorf("-iface is required")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", ifaceName, err)
	}
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
		if objs.DropTCP != nil {
			_ = objs.DropTCP.Close()
		}
	}()

	l, err := link.AttachXDP(link.XDPOptions{Program: objs.DropTCP, Interface: iface.Index})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	fmt.Printf("dropping TCP/443 packets on %s; press Ctrl-C to detach\n", ifaceName)
	<-ctx.Done()
	return nil
}
