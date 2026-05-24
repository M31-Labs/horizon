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
- signed integer literals such as `-1` for signed scalar fields and helpers
- scoped `if name := expr; condition` declarations for short-lived nullable resources
- ringbuf event output
- hash, array, per-CPU, and LRU maps
- explicit `@max_entries(...)` map sizing
- nil-checked map lookups
- bounded counted loops
- explicit integer scalar conversions such as `u64(pid)`
- explicit local variable declarations such as `var pid u32 = bpf.current_pid()`
- explicitly typed constants such as `const Port u16 = 443`
- signed constants such as `const Errno i32 = -1`
- typed enum value groups for named integer actions and flags
- named capability aliases such as `capability ExecObserve = "kernel.process.exec.observe"`
- scalar user helper functions that lower to `static __always_inline` C
- compiler-known kernel helpers
- typed kprobe argument and kretprobe return helpers
- readable generated BPF C
- embedded gotreesitter highlight, locals, and symbol queries for editor integrations
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
    ts_ns u64
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

    event.ts_ns = bpf.ktime_get_ns()
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

Capability strings can be named once at package scope and referenced from
entrypoint attributes. This keeps the source readable while preserving the
manifest's stable Continuum capability name.

```go
capability ExecObserve = "kernel.process.exec.observe"

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
```

Use `enum` for named integer value sets. Enum values are explicit, typed
constants; Horizon does not infer iota-like values or widen them through C's
usual implicit conversions.

```go
enum Verdict i32 {
    VerdictPass = 0
    VerdictDrop = 1
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if bpf.current_pid() == 0 {
        return VerdictPass
    }
    return VerdictDrop
}
```

Use `var` when a local needs an explicit C-facing type. `:=` remains the
preferred shape for nullable resources because Horizon tracks lookup, reserve,
and packet-header ownership from the helper call.

```go
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    var pid u32 = bpf.current_pid()
    var bucket u32 = pid & 0x0f
    return i32(bucket)
}
```

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

    if count := Counts.lookup(pid); count != nil {
        count.seen = count.seen + 1
    }
    return 0
}
```

Reusable logic belongs in small scalar helpers, not in raw C fragments. A
sectionless `func` is a Horizon user helper: it can be called from eBPF
entrypoints or other helpers, must be acyclic, and lowers to readable
`static __always_inline` C so clang and the verifier still see the final code.
In v0, helper parameters and return values are scalar or bool values; resource
ownership stays visible inside the function that reserves or looks up the
resource.

```go
func should_count(pid u32) bool {
    return pid != 0
}

func normalize_pid(pid u32) u32 {
    if should_count(pid) {
        return pid
    }
    return 1
}

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := normalize_pid(bpf.current_pid())
    if should_count(pid) {
        return 0
    }
    return 0
}
```

Maps can be sized deliberately with `@max_entries(...)`. Ringbuf sizes are byte
sizes and must be powers of two; hash and array sizes are entry counts. Use a
literal or an integer constant; Horizon resolves constants before emitting C map
definitions.

```go
const CountEntries u32 = 4096
const EventBytes u32 = 262144

@max_entries(CountEntries)
map Counts hash[u32, Count]

@max_entries(EventBytes)
map ExecEvents ringbuf[ExecEvent]
```

Per-CPU maps are explicit when each CPU should get its own value slot. In
kernel-side `.hzn`, they use the same safe lookup/update/delete flow as ordinary
maps; generated Go bindings expose per-CPU values as typed slices.

```go
type Count struct {
    seen u64
}

map ExecCounts percpu_hash[u32, Count]

@tracepoint("sched:sched_process_exec")
func CountExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if ExecCounts.update(pid, Count{seen: 1}) != 0 {
        return 0
    }

    count := ExecCounts.lookup(pid)
    if count == nil {
        return 0
    }
    count.seen = count.seen + 1
    return 0
}
```

LRU maps are explicit when state should stay bounded and let the kernel evict
least-recently-used entries instead of surfacing map-full failures.

```go
type Flow struct {
    bytes u64
}

@max_entries(8192)
map Flows lru_hash[u64, Flow]

@max_entries(8192)
map CPUFlows lru_percpu_hash[u64, Flow]
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

Tracing programs can also attach to kernel symbols with explicit kprobe and
kretprobe section attributes. Probe contexts stay opaque; use compiler-known
helpers such as `kprobe.arg1(ctx)` and `kretprobe.ret(ctx)` rather than raw
register arithmetic.

```go
package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

type OpenEvent struct {
    pid u32
    dfd i32
    path [256]u8
}

map OpenEvents ringbuf[OpenEvent]

@capability("kernel.file.open.observe")
@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := OpenEvents.reserve()
    if event == nil {
        return 0
    }

    event.pid = bpf.current_pid()
    event.dfd = i32(kprobe.arg1(ctx))
    if bpf.probe_read_user_str(&event.path, kprobe.arg2(ctx)) < 0 {
        OpenEvents.discard(event)
        return 0
    }

    OpenEvents.submit(event)
    return 0
}

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    if rc < 0 {
        return 0
    }
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
    if cgroup.family(ctx) != cgroup.FamilyIPv4 {
        return cgroup.Allow
    }
    if cgroup.protocol(ctx) != cgroup.ProtocolTCP {
        return cgroup.Allow
    }
    if cgroup.dst_port(ctx) == 25 && cgroup.dst_ip4(ctx) != cgroup.ip4(127, 0, 0, 1) {
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
hzn doctor -capabilities dist/exec.cap.json
make setup-vmlinux
make ci-go
hzn workbench ./examples/execwatch -o dist
hzn workbench ./examples/execwatch -o dist -json
hzn workbench ./examples/execwatch -o dist -compile
hzn workbench ./examples/execwatch -o dist -preflight
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
hzn diagnose dist/exec.verifier.log --map dist/exec.hznmap.json -json -fail-on-error
```

`hzn fmt` gives `.hzn` files a canonical AST-based style for local editing and
CI. Use `-w` to update files in place and `-check` to fail when files need
formatting. The formatter preserves standalone and inline line comments.

`hzn workbench` is the authoring path: it validates source and writes readable
BPF C, a source map, typed Go bindings, a capability manifest, diagnostics, and
a report with source file hashes plus artifact kinds, byte sizes, and SHA-256
hashes. The report also includes a compact summary of source count, program
kinds, map kinds, capability danger levels, declared type count, and the
minimum kernel version implied by generated capabilities. Each run removes
stale artifacts for the target output base before writing new ones, records
replaced paths, and includes generator/timestamp provenance in the report.
Use `-preflight` when workbench should run the same host readiness checks as
`hzn doctor -capabilities` against the generated manifest and include that
result in the report.
Invalid programs still produce
`<name>.diagnostics.json` and `<name>.report.json`, including parser failures
before typechecking or C emission can run. Clang failures are remapped into the
same diagnostics artifact, so editors and automation can show actionable
feedback without scraping terminal output. Diagnostics include source-line
context and markers when the authored file is available. Remapped diagnostics keep
the generated BPF C location plus source-map metadata such as Horizon function,
section, and AST node. Common verifier failures also carry Horizon-specific
remediation hints for nil checks, ringbuf lifetimes, bounded loops, helper
availability, and stack usage. Use `-compile` or `hzn build` when the local
clang/BPF C toolchain should also produce a `.bpf.o`.

`hzn diagnose` remaps clang and verifier logs through an `.hznmap.json` source
map. By default it exits successfully when it can explain the log, even when the
log contains errors. Use `-fail-on-error` in CI or editor tasks that should exit
non-zero after emitting remapped diagnostics.

Generated Go bindings expose typed helpers around the loaded objects: ringbuf
maps get `Read<Name>(context.Context, func(Event) error)`, hash maps get
`Lookup<Name>`, `Update<Name>`, `ForEach<Name>`, and `Delete<Name>`, array maps
get `Lookup<Name>`, `Update<Name>`, and `ForEach<Name>`, LRU hash maps use the
same typed hash helpers, per-CPU variants expose typed `[]Value` slices for
lookup/update/iteration, and attachable programs get section-specific attach
methods. The raw `*ebpf.Map` and `*ebpf.Program` fields remain available for
advanced users, but ordinary consumers should not need to hand-roll cilium
loader, memlock, or map-access boilerplate. Bindings also embed
`CapabilityManifestJSON` and expose `CapabilityManifest()` so applications can
inspect the generated capability contract without manually locating the sidecar
manifest.
Ringbuf readers close themselves on context cancellation so blocking reads
unwind through the supplied context.
`LoadObjects` removes the memlock limit by default; use `LoadObjectsWithOptions`
when callers need explicit cilium collection options or custom rlimit behavior.
`hzn check` validates default generated binding names, so collisions with loader,
object, attach, map-helper, and reader APIs fail before artifacts are written.
`make ci-go` typechecks generated bindings for every example so attach helpers,
typed map helpers, and ringbuf readers stay valid against cilium/ebpf.
CI-oriented Make targets keep green logs compact and print captured command
output only when a gate fails.

Generated BPF C and generated Go bindings include scalar width, struct size, and
field offset assertions, so clang or `go test` fails early if an emitted type no
longer matches Horizon's ABI model.

Capability manifests include programs, map access, emitted event names, map key
and value types, and struct size/align/field-offset schemas for declared
Horizon types. They also include minimum kernel requirements for program types,
map kinds, and compiler-known helpers, plus deploy-time permission and host
feature requirements for attach surfaces such as tracefs, XDP, tc, cgroup v2,
and BPF LSM. Continuum consumers can inspect what a program observes, emits, and
needs from a target host without parsing BPF C.
Compiler-known helpers stay explicit: `bpf.ktime_get_ns()` lowers to
`bpf_ktime_get_ns()` and returns a typed `u64` monotonic kernel timestamp.
`bpf.current_ppid()` lowers through a typed CO-RE task read, so the generated C
requires libbpf's `bpf_core_read.h` and a `vmlinux.h` that includes
`struct task_struct` layout.

`hzn doctor` checks the local eBPF C toolchain: clang BPF support, libbpf
headers including CO-RE helpers, bpftool/LLVM utilities, kernel BTF, and a
usable `vmlinux.h`. With `-capabilities`, it also reads a generated capability
manifest and checks the target host against the manifest's minimum kernel,
permission, and attach-feature requirements.
Use `make setup-vmlinux` on BTF-enabled Linux hosts to generate
`/usr/local/include/vmlinux.h`.

## Safety Model

Horizon makes verifier-sensitive behavior explicit before clang runs:

- ringbuf reservations must be nil-checked, submitted, or discarded exactly once
- scoped `if name := expr; condition` declarations lower to a C block before the `if`, so nullable lookup/header/reservation locals can be kept short-lived without leaking outside the branch
- writes after ringbuf submit/discard are rejected
- map lookup results must be nil-checked before field access
- nullable map, packet, and ringbuf resource pointers cannot be copied or aliased
- raw address-taking and explicit pointer dereference are rejected; use compiler-known resource/header helpers and direct fixed-array helper operands instead
- source-authored pointer types such as `*u32` are rejected; nullable pointers only come from compiler-known map lookup, ringbuf reserve, and packet helpers
- struct fields must be unique, and structs are finite by-value records; recursive struct shapes are rejected before C emission
- stored data types for structs and keyed maps must be scalars, fixed arrays, or declared Horizon structs; compiler-owned context and packet header types stay helper-only
- package-scoped declarations cannot use compiler namespace names such as `bpf`, `xdp`, `tc`, `cgroup`, `lsm`, `kprobe`, or `tracepoint`
- default generated Go binding names must be valid and collision-free, so public APIs are checked as part of `hzn check`
- ringbuf maps emit typed events and must use declared struct value types, not scalars or compiler-owned packet/header structs
- map sizing is explicit through `@max_entries(...)`; integer constants are resolved before C emission, and ringbuf sizes must be powers of two
- map update/delete results must be checked with an explicit comparison
- fixed array fields are address-only; pass `&event.comm` directly to helpers instead of copying arrays
- compiler-known helpers have typed signatures and section availability rules before C emission
- conditions must be typed boolean expressions; integers and pointers need explicit comparison
- parser failures are surfaced as stable diagnostics and never produce generated C
- integer, bitwise, comparison, and boolean operators are typed before C emission
- integer width changes are explicit; write `u64(pid)` or `u16(port)` instead of relying on implicit C coercions
- integer literals, literal-backed constants, and literal-backed conversions are checked against their target scalar width before C emission
- unary negation is only allowed for signed scalar values or direct integer literals; unsigned values must be converted deliberately before signed arithmetic
- division and modulo by literal zero are rejected before C emission
- dynamic division and modulo require a divisor proven non-zero by a simple guard or non-zero constant
- literal shift counts must be non-negative and smaller than the left operand width
- dynamic shift counts must be proven non-negative and below the shifted value width with a simple guard
- constants can carry scalar widths, and generated C preserves those widths
- constants are immutable; use locals for values that change inside a program
- enum values are explicit typed integer constants; there is no implicit iota or untyped C enum widening
- `var` declarations require an explicit scalar, bool, or declared struct type and cannot store nullable resources or compiler-owned packet/context types
- sectionless functions are user helpers, not eBPF programs; they are emitted as `static __always_inline` C, must be non-recursive, and currently accept and return only scalar or bool values
- eBPF entrypoint functions cannot be called like helpers; share logic through sectionless helpers so attachable programs remain explicit
- short variable declarations introduce fresh local names only; use `=` to update existing locals, and do not shadow maps or compiler namespaces
- every program must return an explicit `i32` on every control-flow path
- bare `return` is rejected; tracing programs should use `return 0`, while packet and policy programs should return named actions
- only bounded counted loops with numeric literal or integer const upper bounds are accepted
- helper availability is checked against the program kind
- kprobe arguments, safe user string reads, and kretprobe return registers are exposed through typed helper calls, not direct `pt_regs` access
- packet headers returned by `xdp.eth(ctx)`, `xdp.ipv4(ctx)`, `xdp.tcp(ctx)`, and `xdp.udp(ctx)` must be nil-checked before field access
- XDP programs must return named actions such as `xdp.Pass` and `xdp.Drop`, not raw integers
- TC programs must declare `@tc("ingress")` or `@tc("egress")` and return named actions such as `tc.OK` and `tc.Shot`, not raw integers
- cgroup connect programs must declare `@cgroup("connect4")` or `@cgroup("connect6")`, use typed context helpers such as `cgroup.protocol(ctx)` and `cgroup.dst_ip4(ctx)`, and return named actions such as `cgroup.Allow` and `cgroup.Deny`, not raw integers
- cgroup context reads lower through typed generated wrappers, so generated C diagnostics map back to the authored `cgroup.*` helper call
- LSM programs must declare an explicit hook such as `@lsm("file_open")` and return named actions such as `lsm.Allow` and `lsm.Deny`, not raw integers
- generated C emits only the helper and map wrappers the program actually uses
- generated map wrappers source-map back to the authored `lookup`, `update`, `delete`, `reserve`, `submit`, or `discard` call
- generated BPF C is compiled with clang warnings treated as errors
- generated C stays readable so clang and verifier logs remain inspectable
- internal generated C constants and struct tags are prefixed to avoid collisions with kernel headers

## Status

Pre-alpha. The current implementation targets tracepoint, kprobe/kretprobe, TC,
cgroup connect, LSM, and XDP programs with typed ringbuf event output, typed
hash/array/per-CPU/LRU map access, bounded loops, generated BPF C, clang builds,
Go bindings, and Continuum capability manifests.

## License

Apache-2.0. See [LICENSE](LICENSE).
