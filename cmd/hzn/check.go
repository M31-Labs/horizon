package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := compiler.CheckPath(pathArg(fs))
	if err != nil {
		return err
	}
	diagnostics := diagnosticsWithSourceContext(result.Diagnostics, result.Files)
	if *jsonOut {
		if diagnostics == nil {
			diagnostics = []diag.Diagnostic{}
		}
		data, err := json.MarshalIndent(diagnostics, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		if diag.HasErrors(diagnostics) {
			return fmt.Errorf("%d diagnostic(s)", len(diagnostics))
		}
		return nil
	}
	for _, d := range diagnostics {
		fmt.Println(d.Format())
	}
	if diag.HasErrors(diagnostics) {
		return fmt.Errorf("%d diagnostic(s)", len(diagnostics))
	}
	fmt.Printf("check passed: %d file(s)\n", len(result.Files))
	return nil
}
