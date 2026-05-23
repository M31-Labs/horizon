package main

import (
	"flag"
	"fmt"
)

func runDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	_ = fs.String("map", "", "source map path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("diagnose is not implemented yet")
}
