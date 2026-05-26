package validate

import (
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func Program(program ir.Program) []diag.Diagnostic {
	sites := Collect(program)
	var diags []diag.Diagnostic
	diags = append(diags, AnalyzeLoops(program, sites)...)
	diags = append(diags, AnalyzeStack(program, sites)...)
	diags = append(diags, AnalyzeRingbuf(program, sites)...)
	diags = append(diags, AnalyzeMaps(program, sites)...)
	diags = append(diags, AnalyzeHelpers(program, sites)...)
	diags = append(diags, AnalyzePacket(program, sites)...)
	diags = append(diags, ValidateCapabilities(program)...)
	return diags
}
