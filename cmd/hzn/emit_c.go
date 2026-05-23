package main

import (
	"flag"
	"fmt"
)

func runEmitC(args []string) error {
	fs := flag.NewFlagSet("emit-c", flag.ContinueOnError)
	_ = fs.String("o", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("emit-c is not implemented yet")
}
