package main

import (
	"flag"
	"fmt"
)

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	_ = fs.String("o", "dist", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("build is not implemented yet")
}
