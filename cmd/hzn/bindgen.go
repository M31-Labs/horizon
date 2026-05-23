package main

import (
	"flag"

	"m31labs.dev/horizon/bindgen"
)

func runBindgen(args []string) error {
	fs := flag.NewFlagSet("bindgen", flag.ContinueOnError)
	outPath := fs.String("o", "", "output path")
	packageName := fs.String("package", "bindings", "generated Go package name")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	code, err := bindgen.Generate(result.Program, *packageName)
	if err != nil {
		return err
	}
	return writeFile(*outPath, []byte(code))
}
