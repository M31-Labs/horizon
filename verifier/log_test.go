package verifier

import "testing"

func TestParseLogIgnoresVerifierProcessedSummary(t *testing.T) {
	log := ParseLog(`0: R1=ctx() R10=fp0
; bad_access();
invalid mem access 'scalar'
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	if len(log.Entries) != 1 {
		t.Fatalf("entries = %d, want one verifier diagnostic: %#v", len(log.Entries), log.Entries)
	}
	if got, want := log.Entries[0].Message, "invalid mem access 'scalar'"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}
