# VC0006

Provenance: hand-crafted from the canonical `BPF program is too large.
Processed N insn` shape; the trailing `(verification failed)` is appended so
the line trips `looksLikeVerifierDiagnostic` (matches the `failed` marker)
while the catalog regex anchors on the canonical prefix.
