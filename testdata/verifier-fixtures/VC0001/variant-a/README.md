# VC0001 / variant-a

Provenance: hand-crafted from the `invalid mem access 'scalar'` shape in
`verifier/log_test.go:TestParseLogIgnoresVerifierProcessedSummary`, extended
with the typical kernel register-state preamble and a Horizon-flavoured `;`
source line (helper-return dereference without a nil guard). Targets the
first VC0001 pattern (`R\d+ invalid mem access 'scalar'`) — the register
prefix `R2` must be matched and captured.
