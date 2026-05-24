package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type count struct {
	Seen uint64
}

type processCount struct {
	Pid  uint32
	Seen uint64
}

type objects struct {
	ExecCounts *ebpf.Map     `ebpf:"ExecCounts"`
	OnExec     *ebpf.Program `ebpf:"OnExec"`
}

func main() {
	objPath := flag.String("obj", "dist/count.bpf.o", "compiled Horizon eBPF object")
	timeout := flag.Duration("timeout", 10*time.Second, "run duration before printing counts; use 0 to wait for Ctrl-C")
	flag.Parse()

	if err := run(os.Stdout, *objPath, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out io.Writer, objPath string, timeout time.Duration) error {
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

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.OnExec, nil)
	if err != nil {
		return fmt.Errorf("attach sched:sched_process_exec: %w", err)
	}
	defer tp.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	fmt.Fprintln(out, "counting exec events; press Ctrl-C to summarize")
	<-ctx.Done()

	rows, err := readCounts(objs.ExecCounts)
	if err != nil {
		return err
	}
	writeCounts(out, rows)
	return nil
}

func readCounts(m *ebpf.Map) ([]processCount, error) {
	if m == nil {
		return nil, fmt.Errorf("ExecCounts map is not loaded")
	}
	var rows []processCount
	iter := m.Iterate()
	for {
		var pid uint32
		var value count
		if !iter.Next(&pid, &value) {
			break
		}
		rows = append(rows, processCount{Pid: pid, Seen: value.Seen})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate ExecCounts: %w", err)
	}
	sortCounts(rows)
	return rows, nil
}

func sortCounts(rows []processCount) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Seen == rows[j].Seen {
			return rows[i].Pid < rows[j].Pid
		}
		return rows[i].Seen > rows[j].Seen
	})
}

func writeCounts(out io.Writer, rows []processCount) {
	fmt.Fprintln(out, "PID\tEXECS")
	for _, row := range rows {
		fmt.Fprintf(out, "%d\t%d\n", row.Pid, row.Seen)
	}
}

func closeObjects(objs *objects) {
	if objs == nil {
		return
	}
	if objs.ExecCounts != nil {
		_ = objs.ExecCounts.Close()
	}
	if objs.OnExec != nil {
		_ = objs.OnExec.Close()
	}
}
