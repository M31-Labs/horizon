# VC0003

Provenance: hand-crafted from the `invalid access to map_value` shape used
throughout the kernel `tools/testing/selftests/bpf/verifier/bounds*.c`
corpus. Targets the `invalid access to (?:map_value|packet|stack)` pattern;
the offset (4096) clearly exceeds the value size (16) so the verifier
proves OOB statically.
