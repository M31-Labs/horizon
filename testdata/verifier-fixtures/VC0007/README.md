# VC0007

Provenance: transcribed from the canonical `unknown func bpf_*` shape the
kernel verifier emits when a program type is not on a helper's allowlist.
This is the same diagnostic surface already exercised in
`verifier/log_test.go` via the `unknown func` marker; the catalog adds the
`helper` capture (`bpf_(?P<helper>\w+)`) so the remediation can name the
offending helper.
