# Horizon

Go-shaped eBPF authoring for the kernel boundary.

Horizon is not a Go compiler. It is a small Go-shaped DSL for writing
verifier-friendly eBPF programs that lower to readable BPF C.

## Pipeline

```text
.hzn -> AST -> BPF IR -> validation -> C -> clang -> .bpf.o -> bindings
```

## Commands

```sh
hzn check ./examples/execwatch
hzn doctor
make setup-vmlinux
hzn workbench ./examples/execwatch -o dist
hzn workbench ./examples/execwatch -o dist -compile
hzn build ./examples/execwatch -o dist
go run ./examples/execwatch/cmd/execwatch -obj dist/exec.bpf.o
hzn diagnose dist/exec.verifier.log --map dist/exec.hznmap.json
```

`hzn workbench` is the authoring path: it validates source and writes readable
BPF C, a source map, typed Go bindings, a capability manifest, and a report.
Use `-compile` or `hzn build` when the local clang/BPF C toolchain should also
produce a `.bpf.o`.

`hzn doctor` checks the local eBPF C toolchain: clang BPF support, libbpf
headers, bpftool/LLVM utilities, kernel BTF, and a usable `vmlinux.h`.
Use `make setup-vmlinux` on BTF-enabled Linux hosts to generate
`/usr/local/include/vmlinux.h`.

## Status

Pre-alpha. The first implementation target is tracepoint programs that emit
typed events through ring buffers.
