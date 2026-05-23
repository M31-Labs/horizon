package main

import (
	"flag"
	"fmt"
)

func runCapabilities(args []string) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	_ = fs.String("o", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("capabilities is not implemented yet")
}
