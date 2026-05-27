# VC0002

Provenance: hand-crafted from the kernel `invalid mem access 'inv'` shape in
the verifier selftests `tools/testing/selftests/bpf/verifier/value_ptr.c`
family. Targets the `R\d+ invalid mem access 'inv'` pattern — a scalar
value with no provenance used where a pointer was expected.
