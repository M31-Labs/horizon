package verifier

import (
	"testing"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func TestRemapClangDiagnosticToHorizonSource(t *testing.T) {
	sourceMap := testSourceMap(57)
	log := ParseLog(`/tmp/exec.bpf.c:57:5: error: call to undeclared function 'hzn_bad'`)

	diags := Remap(log, sourceMap)
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diags))
	}
	if got, want := diags[0].Span.File, span.FileID("examples/execwatch/exec.hzn"); got != want {
		t.Fatalf("span file = %q, want %q", got, want)
	}
	if got, want := diags[0].Span.Start.Line, 25; got != want {
		t.Fatalf("span line = %d, want %d", got, want)
	}
	if got, want := diags[0].Generated.Start.Line, 57; got != want {
		t.Fatalf("generated line = %d, want %d", got, want)
	}
}

func TestRemapVerifierSourceCommentToHorizonSource(t *testing.T) {
	sourceMap := testSourceMap(3)
	generated := []byte(`SEC("tracepoint/sched/sched_process_exec")
int OnExec(void *ctx) {
    hzn_current_comm(&event->comm, sizeof(event->comm));
}`)
	log := ParseLog(`0: R1=ctx() R10=fp0
; hzn_current_comm(&event->comm, sizeof(event->comm));
invalid mem access 'scalar'`)

	diags := RemapWithGenerated(log, sourceMap, generated)
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diags))
	}
	if got, want := diags[0].Span.Start.Line, 25; got != want {
		t.Fatalf("span line = %d, want %d", got, want)
	}
	if got, want := diags[0].Generated.Start.Line, 3; got != want {
		t.Fatalf("generated line = %d, want %d", got, want)
	}
}

func testSourceMap(generatedLine int) ir.SourceMap {
	return ir.SourceMap{
		Generated: ir.GeneratedSource{Path: "/tmp/exec.bpf.c", Language: "c"},
		Mappings: []ir.SourceMapping{
			{
				Source: span.Span{
					File:  "examples/execwatch/exec.hzn",
					Start: span.Point{Line: 25, Column: 5},
					End:   span.Point{Line: 25, Column: 34},
				},
				Generated: span.Span{
					Start: span.Point{Line: generatedLine, Column: 1},
					End:   span.Point{Line: generatedLine + 1, Column: 1},
				},
				Node:     "expr",
				Function: "OnExec",
				Section:  "tracepoint/sched/sched_process_exec",
			},
		},
	}
}
