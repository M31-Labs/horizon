# Horizon

Go-shaped eBPF authoring for the kernel boundary.

Horizon is not a Go compiler. It is a small Go-shaped DSL for writing
verifier-friendly eBPF programs that lower to readable BPF C.

It keeps the kernel-side language deliberately small:

- tracepoint programs
- kprobe and kretprobe programs
- XDP programs
- TC classifier programs
- cgroup connect programs
- LSM programs
- typed structs and fixed arrays
- boolean literals and typed boolean expressions
- package-scoped declarations across multiple `.hzn` files
- integer constants with optional scalar widths
- ringbuf event output
- hash and array maps
- nil-checked map lookups
- bounded counted loops
- explicit integer scalar conversions such as `u64(pid)`
- explicitly typed constants such as `const Port u16 = 443`
- compiler-known kernel helpers
- readable generated BPF C
- source maps with declaration and function/section context for diagnostics
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
const FirstSeen u32 = 1

type Count struct {
    seen u32
}

map Counts hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, Count{seen: FirstSeen}) != 0 {
        return 0
    }

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

    port := xdp.ntohs(tcp.dst_port)
    if (port == 443) && ((tcp.data_off & 0x0f) != 0) {
        return xdp.Drop
    }

    return xdp.Pass
}
```

Tracing programs can also attach to kernel symbols with explicit kprobe section
attributes. v0 keeps kprobe contexts opaque; use compiler-known helpers and
typed maps/events rather than raw register arithmetic.

```go
package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@capability("kernel.file.open.observe")
@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    bpf.current_pid()
    return 0
}
```

TC classifier programs are explicit about direction and return named TC actions,
not raw integers.

```go
package probes

@capability("kernel.network.tc.observe")
@tc("ingress")
func PassIngress(ctx tc.Context) i32 {
    return tc.OK
}
```

Cgroup connect programs make policy decisions with named allow/deny actions.
Compiler-known helpers expose small, typed pieces of the kernel context instead
of making authors poke raw `struct bpf_sock_addr` fields.

```go
package probes

@capability("kernel.network.connect.block")
@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.dst_port(ctx) == 25 {
        return cgroup.Deny
    }
    return cgroup.Allow
}
```

LSM programs are policy hooks with opaque contexts in v0. They return named
allow/deny actions so authoring stays explicit about security impact.

```go
package probes

@capability("kernel.file.open.block")
@lsm("file_open")
func DenyFileOpen(ctx lsm.Context) i32 {
    return lsm.Deny
}
```

## Commands

```sh
hzn check ./examples/execwatch
hzn check ./examples/execwatch -json
hzn fmt ./examples/execwatch
hzn fmt ./examples -w
hzn fmt ./examples -check
hzn doctor
make setup-vmlinux
hzn workbench ./examples/execwatch -o dist
hzn workbench ./examples/execwatch -o dist -json
hzn workbench ./examples/execwatch -o dist -compile
hzn build ./examples/cgroupconnect -o dist
sudo go run ./examples/cgroupconnect/cmd/cgroupconnect -obj dist/connect.bpf.o -cgroup /sys/fs/cgroup
hzn build ./examples/execwatch -o dist
go run ./examples/execwatch/cmd/execwatch -obj dist/exec.bpf.o
hzn build ./examples/execcount -o dist
sudo go run ./examples/execcount/cmd/execcount -obj dist/count.bpf.o -timeout 10s
hzn build ./examples/lsmfile -o dist
sudo go run ./examples/lsmfile/cmd/lsmfile -obj dist/file.bpf.o
hzn build ./examples/openwatch -o dist
sudo go run ./examples/openwatch/cmd/openwatch -obj dist/open.bpf.o
hzn build ./examples/tcpconnect -o dist
sudo go run ./examples/tcpconnect/cmd/tcpconnect -obj dist/tcp.bpf.o
hzn build ./examples/tcpass -o dist
sudo go run ./examples/tcpass/cmd/tcpass -obj dist/tc.bpf.o -iface lo
hzn build ./examples/xdpdrop -o dist
sudo go run ./examples/xdpdrop/cmd/xdpdrop -obj dist/xdp.bpf.o -iface lo
hzn diagnose dist/exec.verifier.log --map dist/exec.hznmap.json
```

`hzn fmt` gives `.hzn` files a canonical AST-based style for local editing and
CI. Use `-w` to update files in place and `-check` to fail when files need
formatting. The v0 formatter refuses files with line comments until comment
preservation is implemented.

`hzn workbench` is the authoring path: it validates source and writes readable
BPF C, a source map, typed Go bindings, a capability manifest, diagnostics, and
a report with source file hashes plus artifact kinds, byte sizes, and SHA-256
hashes. Each run removes stale artifacts for the target output base before
writing new ones, records replaced paths, and includes generator/timestamp
provenance in the report. Invalid programs still produce
`<name>.diagnostics.json` and `<name>.report.json`, including parser failures
before typechecking or C emission can run. Clang failures are remapped into the
same diagnostics artifact, so editors and automation can show actionable
feedback without scraping terminal output. Remapped diagnostics keep
the generated BPF C location plus source-map metadata such as Horizon function,
section, and AST node. Use `-compile` or `hzn build` when the local clang/BPF C
toolchain should also produce a `.bpf.o`.

Generated Go bindings expose typed helpers around the loaded objects: ringbuf
maps get `Read<Name>(context.Context, func(Event) error)`, hash maps get
`Lookup<Name>`, `Update<Name>`, `ForEach<Name>`, and `Delete<Name>`, array maps
get `Lookup<Name>`, `Update<Name>`, and `ForEach<Name>`, and attachable programs
get section-specific attach methods. The raw `*ebpf.Map` and `*ebpf.Program`
fields remain available for advanced users, but ordinary consumers should not
need to hand-roll cilium loader, memlock, or map-access boilerplate.
Ringbuf readers close themselves on context cancellation so blocking reads
unwind through the supplied context.
`LoadObjects` removes the memlock limit by default; use `LoadObjectsWithOptions`
when callers need explicit cilium collection options or custom rlimit behavior.

Generated BPF C and generated Go bindings include scalar width, struct size, and
field offset assertions, so clang or `go test` fails early if an emitted type no
longer matches Horizon's ABI model.

Capability manifests include programs, map access, emitted event names, map key
and value types, and struct size/align/field-offset schemas for declared
Horizon types. Continuum consumers can inspect what a program observes or emits
without parsing BPF C.

`hzn doctor` checks the local eBPF C toolchain: clang BPF support, libbpf
headers, bpftool/LLVM utilities, kernel BTF, and a usable `vmlinux.h`.
Use `make setup-vmlinux` on BTF-enabled Linux hosts to generate
`/usr/local/include/vmlinux.h`.

## Safety Model

Horizon makes verifier-sensitive behavior explicit before clang runs:

- ringbuf reservations must be nil-checked, submitted, or discarded exactly once
- writes after ringbuf submit/discard are rejected
- map lookup results must be nil-checked before field access
- nullable map, packet, and ringbuf resource pointers cannot be copied or aliased
- map update/delete results must be checked with an explicit comparison
- fixed array fields are address-only; pass `&event.comm` directly to helpers instead of copying arrays
- conditions must be typed boolean expressions; integers and pointers need explicit comparison
- parser failures are surfaced as stable diagnostics and never produce generated C
- integer, bitwise, comparison, and boolean operators are typed before C emission
- integer width changes are explicit; write `u64(pid)` or `u16(port)` instead of relying on implicit C coercions
- constants can carry scalar widths, and generated C preserves those widths
- every program must return an explicit `i32` on every control-flow path
- only bounded counted loops are accepted
- helper availability is checked against the program kind
- packet headers returned by `xdp.eth(ctx)`, `xdp.ipv4(ctx)`, `xdp.tcp(ctx)`, and `xdp.udp(ctx)` must be nil-checked before field access
- XDP programs must return named actions such as `xdp.Pass` and `xdp.Drop`, not raw integers
- TC programs must declare `@tc("ingress")` or `@tc("egress")` and return named actions such as `tc.OK` and `tc.Shot`, not raw integers
- cgroup connect programs must declare `@cgroup("connect4")` or `@cgroup("connect6")` and return named actions such as `cgroup.Allow` and `cgroup.Deny`, not raw integers
- LSM programs must declare an explicit hook such as `@lsm("file_open")` and return named actions such as `lsm.Allow` and `lsm.Deny`, not raw integers
- generated C emits only the helper and map wrappers the program actually uses
- generated BPF C is compiled with clang warnings treated as errors
- generated C stays readable so clang and verifier logs remain inspectable
- internal generated C constants and struct tags are prefixed to avoid collisions with kernel headers

## Status

Pre-alpha. The current implementation targets tracepoint, kprobe/kretprobe, TC,
cgroup connect, LSM, and XDP programs with typed ringbuf event output, typed
hash/array map access, bounded loops, generated BPF C, clang builds, Go
bindings, and Continuum capability manifests.
