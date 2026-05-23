# Horizon

Go-shaped eBPF authoring for the kernel boundary.

Horizon is not a Go compiler. It is a small Go-shaped DSL for writing
verifier-friendly eBPF programs that lower to readable BPF C.

## Pipeline

```text
.hzn -> AST -> BPF IR -> validation -> C -> clang -> .bpf.o -> bindings
```

## Status

Pre-alpha. The first implementation target is tracepoint programs that emit
typed events through ring buffers.

