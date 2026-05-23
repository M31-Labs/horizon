package main

import (
	"flag"

	"m31labs.dev/horizon/emitc"
)

func runEmitC(args []string) error {
	fs := flag.NewFlagSet("emit-c", flag.ContinueOnError)
	outPath := fs.String("o", "", "output path")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	output, err := emitc.Emit(result.Program)
	if err != nil {
		return err
	}
	if *outPath != "" {
		output.SourceMap.Generated.Path = *outPath
	}
	if err := writeFile(*outPath, []byte(output.Code)); err != nil {
		return err
	}
	if *outPath != "" {
		return writeJSON(sourceMapPath(*outPath), output.SourceMap)
	}
	return nil
}
