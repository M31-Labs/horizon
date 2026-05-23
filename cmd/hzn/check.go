package main

import (
	"flag"
	"fmt"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *jsonOut {
		return fmt.Errorf("JSON diagnostics are not implemented yet")
	}
	result, err := compiler.CheckPath(pathArg(fs))
	if err != nil {
		return err
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
