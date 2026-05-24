package main

import (
	"flag"

	"m31labs.dev/horizon/compiler/diag"
)

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	outDir := fs.String("o", "dist", "output directory")
	packageName := fs.String("package", "bindings", "generated Go package name")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	report, err := writeWorkbenchArtifacts(result, workbenchOptions{
		OutDir:      *outDir,
		PackageName: *packageName,
		Compile:     true,
	})
	if err != nil && diag.HasErrors(report.Diagnostics) {
		printDiagnostics(report.Diagnostics)
		return errDiagnostics(report.DiagnosticCount)
	}
	return err
}
