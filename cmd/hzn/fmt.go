package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"m31labs.dev/horizon/compiler"
	hznformat "m31labs.dev/horizon/format"
	"m31labs.dev/horizon/parser"
)

func runFmt(args []string) error {
	fs := flag.NewFlagSet("fmt", flag.ContinueOnError)
	write := fs.Bool("w", false, "write formatted source back to files")
	check := fs.Bool("check", false, "check whether files are formatted")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *write && *check {
		return fmt.Errorf("fmt -w and -check cannot be used together")
	}
	paths, err := compiler.CollectFiles(pathArg(fs))
	if err != nil {
		return err
	}
	if !*write && !*check && len(paths) != 1 {
		return fmt.Errorf("fmt over multiple files requires -w or -check")
	}
	var unformatted []string
	for _, path := range paths {
		source, err := parser.ReadSource(path)
		if err != nil {
			return err
		}
		formatted, err := hznformat.Source(source)
		if err != nil {
			return err
		}
		switch {
		case *write:
			if bytes.Equal(source.Bytes, formatted) {
				continue
			}
			if err := os.WriteFile(path, formatted, 0o644); err != nil {
				return err
			}
		case *check:
			if bytes.Equal(source.Bytes, formatted) {
				continue
			}
			unformatted = append(unformatted, path)
		default:
			if _, err := os.Stdout.Write(formatted); err != nil {
				return err
			}
		}
	}
	if len(unformatted) > 0 {
		for _, path := range unformatted {
			fmt.Fprintf(os.Stderr, "%s is not formatted\n", path)
		}
		return fmt.Errorf("%d file(s) need formatting", len(unformatted))
	}
	return nil
}
