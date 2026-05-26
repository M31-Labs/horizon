package emitc_test

import (
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/emitc"
)

func TestSourceMapPopulatedByEmit(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", result.Diagnostics)
	}
	out, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(out.SourceMap.Mappings) == 0 {
		t.Fatal("emitc.Output.SourceMap.Mappings empty; expected populated map")
	}
	if !strings.Contains(out.Code, "OnExec") {
		t.Fatal("emitted C missing OnExec; example fixture broke")
	}
}

// TestEmitProducesFreshSourceMapPerCall verifies that calling Emit twice on the
// same ir.Program produces independent SourceMap.Mappings slices — no shared
// mutable state between calls.
func TestEmitProducesFreshSourceMapPerCall(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}

	out1, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit (first call): %v", err)
	}
	out2, err := emitc.Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit (second call): %v", err)
	}

	if len(out1.SourceMap.Mappings) == 0 {
		t.Fatal("first Emit produced empty SourceMap.Mappings")
	}
	if len(out2.SourceMap.Mappings) == 0 {
		t.Fatal("second Emit produced empty SourceMap.Mappings")
	}

	// Mutate the first result's slice and confirm the second is unaffected.
	original := out2.SourceMap.Mappings[0]
	out1.SourceMap.Mappings[0] = out1.SourceMap.Mappings[len(out1.SourceMap.Mappings)-1]
	if out2.SourceMap.Mappings[0] != original {
		t.Fatal("SourceMap.Mappings slices share underlying array; Emit is not producing independent maps")
	}
}
