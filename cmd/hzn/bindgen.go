package main

import (
	"flag"
	"fmt"
)

func runBindgen(args []string) error {
	fs := flag.NewFlagSet("bindgen", flag.ContinueOnError)
	_ = fs.String("o", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("bindgen is not implemented yet")
}
