# Horizon

Go-shaped eBPF authoring for the kernel boundary.

Horizon is not a Go compiler. It is a small Go-shaped DSL for writing
verifier-friendly eBPF programs that lower to readable BPF C.

It keeps the kernel-side language deliberately small:

- tracepoint programs
- XDP programs
- typed structs and fixed arrays
- ringbuf event output
- hash and array maps
- nil-checked map lookups
- bounded counted loops
- compiler-known kernel helpers
- readable generated BPF C
- source maps for diagnostics
- typed Go bindings and Continuum capability manifests

## Pipeline

```text
.hzn -> gotreesitter parser -> AST -> BPF IR -> validation -> C -> clang -> .bpf.o -> bindings + capabilities
```

## Example

```go
package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

type ExecEvent struct {
    pid  u32
    ppid u32
    uid  u32
    comm [16]u8
}

map ExecEvents ringbuf[ExecEvent]

@capability("kernel.process.exec.observe")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := ExecEvents.reserve()
    if event == nil {
        return 0
    }

    event.pid = bpf.current_pid()
    event.ppid = bpf.current_ppid()
    event.uid = bpf.current_uid()
    bpf.current_comm(&event.comm)

    ExecEvents.submit(event)
    return 0
}
```

Stateful programs can use typed maps. Lookup results are nullable and must be
checked before dereference.

```go
type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    Counts.update(pid, Count{seen: 1})

    count := Counts.lookup(pid)
    if count == nil {
        return 0
    }

    count.seen = bpf.current_pid()
    return 0
}
```

Packet-path programs use explicit section attributes, compiler-checked packet
loads, nil-checked headers, and named action values instead of raw pointer
arithmetic or integer returns.

```go
package probes

@capability("kernel.network.xdp.drop")
@xdp
func DropTCP(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    if xdp.ntohs(tcp.dst_port) == 443 {
        return xdp.Drop
    }

    return xdp.Pass
}
```

## Commands

```sh
hzn check ./examples/execwatch
hzn check ./examples/execwatch -json
hzn doctor
make setup-vmlinux
hzn workbench ./examples/execwatch -o dist
hzn workbench ./examples/execwatch -o dist -compile
hzn build ./examples/execwatch -o dist
go run ./examples/execwatch/cmd/execwatch -obj dist/exec.bpf.o
hzn build ./examples/xdpdrop -o dist
sudo go run ./examples/xdpdrop/cmd/xdpdrop -obj dist/xdp.bpf.o -iface lo
hzn diagnose dist/exec.verifier.log --map dist/exec.hznmap.json
```

`hzn workbench` is the authoring path: it validates source and writes readable
BPF C, a source map, typed Go bindings, a capability manifest, diagnostics, and
a report. Invalid programs still produce `<name>.diagnostics.json` and
`<name>.report.json`, so editors and automation can show actionable feedback
without scraping terminal output. Use `-compile` or `hzn build` when the local
clang/BPF C toolchain should also produce a `.bpf.o`.

`hzn doctor` checks the local eBPF C toolchain: clang BPF support, libbpf
headers, bpftool/LLVM utilities, kernel BTF, and a usable `vmlinux.h`.
Use `make setup-vmlinux` on BTF-enabled Linux hosts to generate
`/usr/local/include/vmlinux.h`.

## Safety Model

Horizon makes verifier-sensitive behavior explicit before clang runs:

- ringbuf reservations must be nil-checked, submitted, or discarded exactly once
- writes after ringbuf submit/discard are rejected
- map lookup results must be nil-checked before field access
- fixed array fields are address-only; pass `&event.comm` directly to helpers instead of copying arrays
- only bounded counted loops are accepted
- helper availability is checked against the program kind
- packet headers returned by `xdp.eth(ctx)`, `xdp.ipv4(ctx)`, `xdp.tcp(ctx)`, and `xdp.udp(ctx)` must be nil-checked before field access
- XDP programs return named actions such as `xdp.Pass` and `xdp.Drop`
- generated C stays readable so clang and verifier logs remain inspectable

## Status

Pre-alpha. The current implementation targets tracepoint and XDP programs with
typed ringbuf event output, typed hash/array map access, bounded loops,
generated BPF C, clang builds, Go bindings, and Continuum capability manifests.
