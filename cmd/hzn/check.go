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
	if *jsonOut {
		diagnostics := result.Diagnostics
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
		if diag.HasErrors(result.Diagnostics) {
			return fmt.Errorf("%d diagnostic(s)", len(result.Diagnostics))
		}
		return nil
	}
	for _, d := range result.Diagnostics {
		fmt.Println(d.Format())
	}
	if diag.HasErrors(result.Diagnostics) {
		return fmt.Errorf("%d diagnostic(s)", len(result.Diagnostics))
	}
	fmt.Printf("check passed: %d file(s)\n", len(result.Files))
	return nil
}
