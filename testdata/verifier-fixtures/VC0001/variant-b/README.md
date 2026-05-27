# VC0001 / variant-b

Provenance: hand-crafted. Strips the register-state preamble so the message
is the bare `invalid mem access 'scalar'` line. Targets the second VC0001
pattern (no `R\d+` prefix). If the alternation in the catalog regex were
dropped to the single register-prefixed pattern, this fixture would no
longer match VC0001 — that's the property the variant pair exists to pin.
