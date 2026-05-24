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
	case "workbench":
		return runWorkbench(rest)
	case "fmt":
		return runFmt(rest)
	case "doctor":
		return runDoctor(rest)
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
	fmt.Fprintln(os.Stderr, "Usage: hzn <check|fmt|workbench|build|doctor|emit-c|bindgen|diagnose|capabilities> [path] [flags]")
}

func pathArg(fs *flag.FlagSet) string {
	if fs.NArg() > 0 {
		return fs.Arg(0)
	}
	return "."
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorderFlags(args))
}

func reorderFlags(args []string) []string {
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) > 0 && arg[0] == '-' {
			flags = append(flags, arg)
			if flagNeedsValue(arg) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func flagNeedsValue(arg string) bool {
	if len(arg) >= 2 && arg[0:2] == "--" {
		arg = arg[1:]
	}
	for _, name := range []string{"-o", "-map", "-generated", "-package", "-capabilities"} {
		if arg == name || len(arg) > len(name) && arg[:len(name)+1] == name+"=" {
			return arg == name
		}
	}
	return false
}
