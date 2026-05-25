package verifier

import (
	"strings"
	"testing"
)

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
	if got := log.Entries[0].Raw; got == "" || got == log.Entries[0].Message {
		t.Fatalf("raw context = %q, want verifier context plus diagnostic", got)
	}
}

func TestParseLogPreservesRecentVerifierContext(t *testing.T) {
	log := ParseLog(`0: R1=ctx() R10=fp0
1: R1_w=scalar()
; event->pid = bpf.current_pid();
2: (7b) *(u64 *)(r10 -8) = r1
invalid mem access 'scalar'
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	if len(log.Entries) != 1 {
		t.Fatalf("entries = %d, want one verifier diagnostic: %#v", len(log.Entries), log.Entries)
	}
	wantLines := []string{
		"0: R1=ctx() R10=fp0",
		"1: R1_w=scalar()",
		"; event->pid = bpf.current_pid();",
		"2: (7b) *(u64 *)(r10 -8) = r1",
		"invalid mem access 'scalar'",
	}
	for _, line := range wantLines {
		if !strings.Contains(log.Entries[0].Raw, line) {
			t.Fatalf("raw context = %q, missing %q", log.Entries[0].Raw, line)
		}
	}
	if strings.Contains(log.Entries[0].Raw, "processed 12 insns") {
		t.Fatalf("raw context includes verifier summary: %q", log.Entries[0].Raw)
	}
}
