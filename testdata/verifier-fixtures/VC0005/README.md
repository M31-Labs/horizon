# VC0005

Provenance: hand-crafted from the `back-edge from insn N to M` shape the
kernel verifier emits when it rejects an unbounded loop. The synthetic log
combines `unbounded loop detected` (which trips `looksLikeVerifierDiagnostic`
via the `unbounded` marker) with the canonical `back-edge from insn N to M`
phrasing the catalog regex anchors on.
