# VC0009

Provenance: hand-crafted from the canonical `combined stack size of N calls
is M. Too large` shape; the trailing `(verification failed)` is appended so
the line trips `looksLikeVerifierDiagnostic` while the catalog regex anchors
on the canonical phrasing. Models a call chain whose summed frame sizes
exceed the 512-byte BPF stack budget.
