# Contributing

Horizon is a small Go-shaped DSL for authoring verifier-friendly eBPF programs
that lower to readable C. Contributions should preserve that identity:

- do not add broad Go compatibility unless it has explicit eBPF semantics
- keep ownership, nil checks, and resource lifetimes visible in `.hzn`
- prefer typed compiler-known helpers over raw pointer or C escape hatches
- keep generated C readable enough for clang and verifier diagnostics

## Development

Use Go 1.24.x. The main local gates are:

```sh
go test ./...
make ci-go
make ci-clang OUT=/tmp/horizon-ci
```

`make ci-go` covers Go type-checking, the test suite, formatter check on
`./examples`, and bindings smoke tests against `cilium/ebpf`. To run just
the formatter check on its own:

```sh
go run ./cmd/hzn fmt ./examples -check
go run ./cmd/hzn fmt ./examples -w   # to apply
```

`make ci-clang` requires clang, LLVM, libbpf headers, and a usable
`vmlinux.h`. On Linux hosts with kernel BTF, run:

```sh
make setup-vmlinux
```

A pull request is ready for review when both `make ci-go` and
`make ci-clang` pass locally.

Generated artifacts such as `.bpf.c`, `.bpf.o`, `.hznmap.json`,
`.bindings.go`, `.cap.json`, diagnostics, and reports should stay out of git
unless they are intentional golden test fixtures.

## Tests

Add focused tests near the behavior being changed:

- parser and AST tests for syntax
- typechecker tests for diagnostics and safety rules
- C emitter tests for readable generated C
- golden tests when artifact shape changes
- clang smoke coverage when generated C semantics change

Negative tests should assert stable Horizon diagnostic codes.

## License

By contributing, you agree that your contributions are licensed under the
Apache License, Version 2.0.
