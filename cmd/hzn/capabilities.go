package main

import (
	"flag"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
)

func runCapabilities(args []string) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	outPath := fs.String("o", "", "output path")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	manifest := capability.FromIR(result.Program)
	if err := capability.Validate(manifest); err != nil {
		if d, ok := capability.DiagnosticForError(err); ok {
			printDiagnostics(diagnosticsWithSourceContext([]diag.Diagnostic{d}, result.Files))
			return errDiagnostics(1)
		}
		return err
	}
	return writeJSON(*outPath, manifest)
}
