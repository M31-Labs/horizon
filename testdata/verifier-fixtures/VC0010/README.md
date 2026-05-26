# VC0010

Provenance: hand-crafted from the canonical `misaligned (stack|packet|value)
access` shape; offset -7 is not 4-byte aligned, so the verifier rejects the
u32 load statically. Same diagnostic surface as the `misaligned` marker
already in `verifier/log.go:looksLikeVerifierDiagnostic`.
