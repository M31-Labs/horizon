package compiler

import (
	"slices"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func TestAnalyzeExecwatchPasses(t *testing.T) {
	result, err := AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if diag.HasErrors(result.Diagnostics) {
		t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
	}
	if result.Program.Package != "probes" {
		t.Fatalf("package = %q, want probes", result.Program.Package)
	}
	if len(result.Program.Functions) != 1 || len(result.Program.Maps) != 1 || len(result.Program.Capabilities) != 1 {
		t.Fatalf("program = %#v, want one function, map, and capability", result.Program)
	}
}

func TestAnalyzeInvalidRingbufPrograms(t *testing.T) {
	tests := map[string]string{
		"../testdata/invalid/ringbuf_missing_nil_check.hzn":  "HZN2100",
		"../testdata/invalid/ringbuf_write_after_submit.hzn": "HZN2103",
		"../testdata/invalid/ringbuf_double_submit.hzn":      "HZN2102",
		"../testdata/invalid/ringbuf_live_on_return.hzn":     "HZN2104",
		"../testdata/invalid/unbounded_loop.hzn":             "HZN2200",
	}
	for path, code := range tests {
		result, err := AnalyzePath(path)
		if err != nil {
			t.Fatalf("AnalyzePath(%s): %v", path, err)
		}
		if !slices.ContainsFunc(result.Diagnostics, func(d diag.Diagnostic) bool {
			return d.Code == code
		}) {
			t.Fatalf("AnalyzePath(%s) diagnostics = %#v, want %s", path, result.Diagnostics, code)
		}
	}
}
