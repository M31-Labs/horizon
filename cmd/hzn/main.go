package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "check":
		return runCheck(rest)
	case "emit-c":
		return runEmitC(rest)
	case "build":
		return runBuild(rest)
	case "bindgen":
		return runBindgen(rest)
	case "diagnose":
		return runDiagnose(rest)
	case "capabilities":
		return runCapabilities(rest)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: hzn <check|emit-c|build|bindgen|diagnose|capabilities> [path] [flags]")
}

func pathArg(fs *flag.FlagSet) string {
	if fs.NArg() > 0 {
		return fs.Arg(0)
	}
	return "."
}
