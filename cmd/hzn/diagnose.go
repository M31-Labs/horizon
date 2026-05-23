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
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
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
	var generated []byte
	if sourceMap.Generated.Path != "" {
		if data, err := os.ReadFile(sourceMap.Generated.Path); err == nil {
			generated = data
		}
	}
	diagnostics := verifier.RemapWithGenerated(verifier.ParseLog(string(raw)), sourceMap, generated)
	if *jsonOut {
		data, err := json.MarshalIndent(diagnostics, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		_, err = os.Stdout.Write(data)
		return err
	}
	for _, d := range diagnostics {
		if d.Span.IsZero() {
			fmt.Println(d.Message)
			continue
		}
		fmt.Printf("%s --> %s:%d:%d\n", d.Message, d.Span.File, d.Span.Start.Line, d.Span.Start.Column)
		if !d.Generated.IsZero() {
			fmt.Printf("  generated: %s:%d:%d\n", d.Generated.File, d.Generated.Start.Line, d.Generated.Start.Column)
		}
	}
	return nil
}
