package validate

import (
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func Program(program ir.Program) []diag.Diagnostic {
	sites := Collect(program)
	// Build the user-helper effect summary once per program. Each validator
	// that tracks a nullable resource (ringbuf today; maps/packet in later
	// Phase 2 #13 tasks) consults this summary to propagate caller-side
	// state across user-helper call sites. Cost is one walk per user helper.
	effects := BuildHelperEffects(program)
	var diags []diag.Diagnostic
	diags = append(diags, AnalyzeLoops(program, sites)...)
	diags = append(diags, AnalyzeStack(program, sites)...)
	diags = append(diags, AnalyzeRingbuf(program, sites, effects)...)
	diags = append(diags, AnalyzeMaps(program, sites, effects)...)
	diags = append(diags, AnalyzeHelpers(program, sites)...)
	diags = append(diags, AnalyzePacket(program, sites, effects)...)
	diags = append(diags, ValidateCapabilities(program)...)
	return diags
}
