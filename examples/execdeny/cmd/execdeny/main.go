package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type objects struct {
	CellScope *ebpf.Map     `ebpf:"CellScope"`
	DenyExec  *ebpf.Program `ebpf:"DenyExec"`
}

type cellScopeVal struct {
	CellLo uint64
	CellHi uint64
	Class  uint32
	FsDev  uint32
}

func main() {
	objPath := flag.String("obj", "dist/exec.bpf.o", "compiled Horizon eBPF object")
	timeout := flag.Duration("timeout", 0, "optional run duration")
	scopeCgroup := flag.Uint64("scope-cgroup", 0, "cgroup v2 ID to deny (defaults to this process's cgroup)")
	flag.Parse()

	if err := run(*objPath, *timeout, *scopeCgroup); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(objPath string, timeout time.Duration, scopeCgroup uint64) error {
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
		if objs.CellScope != nil {
			_ = objs.CellScope.Close()
		}
		if objs.DenyExec != nil {
			_ = objs.DenyExec.Close()
		}
	}()
	if scopeCgroup == 0 {
		scopeCgroup, err = currentCgroupID()
		if err != nil {
			return err
		}
	}
	if objs.CellScope == nil {
		return fmt.Errorf("CellScope map is not loaded")
	}
	if err := objs.CellScope.Update(scopeCgroup, cellScopeVal{Class: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("scope cgroup %d: %w", scopeCgroup, err)
	}

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.DenyExec})
	if err != nil {
		return fmt.Errorf("attach LSM bprm_check_security exec deny: %w", err)
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	fmt.Printf("LSM bprm_check_security exec deny attached for cgroup %d; press Ctrl-C to detach\n", scopeCgroup)
	<-ctx.Done()
	return nil
}

func currentCgroupID() (uint64, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, fmt.Errorf("read current cgroup: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		relative := strings.TrimPrefix(line, "0::")
		path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(relative, "/"))
		info, err := os.Stat(path)
		if err != nil {
			return 0, fmt.Errorf("stat current cgroup %s: %w", path, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Ino == 0 {
			return 0, fmt.Errorf("current cgroup %s has no kernel inode ID", path)
		}
		return stat.Ino, nil
	}
	return 0, fmt.Errorf("unified cgroup v2 entry not found in /proc/self/cgroup")
}
