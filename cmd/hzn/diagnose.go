package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/verifier"
)

func runDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	mapPath := fs.String("map", "", "source map path")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("diagnose requires a clang or verifier log path")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var sourceMap ir.SourceMap
	if *mapPath != "" {
		data, err := os.ReadFile(*mapPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &sourceMap); err != nil {
			return err
		}
	}
	for _, d := range verifier.Remap(verifier.ParseLog(string(raw)), sourceMap) {
		if d.Span.IsZero() {
			fmt.Println(d.Message)
			continue
		}
		fmt.Printf("%s --> %s:%d:%d\n", d.Message, d.Span.File, d.Span.Start.Line, d.Span.Start.Column)
	}
	return nil
}
