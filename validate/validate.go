package validate

import (
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func Program(program ir.Program) []diag.Diagnostic {
	var diags []diag.Diagnostic
	diags = append(diags, ValidateLoops(program)...)
	diags = append(diags, ValidateStack(program)...)
	diags = append(diags, ValidateRingbuf(program)...)
	diags = append(diags, ValidateMaps(program)...)
	diags = append(diags, ValidateHelpers(program)...)
	diags = append(diags, ValidatePacket(program)...)
	diags = append(diags, ValidateCapabilities(program)...)
	return diags
}
