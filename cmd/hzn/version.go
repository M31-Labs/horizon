package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

const modulePath = "m31labs.dev/horizon"

var (
	buildVersion = "devel"
	buildCommit  = ""
	buildDate    = ""
)

type toolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Module    string `json:"module"`
	Commit    string `json:"commit,omitempty"`
	BuiltAt   string `json:"built_at,omitempty"`
	Modified  bool   `json:"modified"`
	GoVersion string `json:"go_version"`
}

func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON version metadata")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("version does not take a path argument")
	}
	info := currentToolInfo()
	if *jsonOut {
		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		_, err = os.Stdout.Write(data)
		return err
	}
	fmt.Fprintf(os.Stdout, "hzn %s\n", info.Version)
	fmt.Fprintf(os.Stdout, "module: %s\n", info.Module)
	if info.Commit != "" {
		fmt.Fprintf(os.Stdout, "commit: %s\n", info.Commit)
	}
	if info.BuiltAt != "" {
		fmt.Fprintf(os.Stdout, "built_at: %s\n", info.BuiltAt)
	}
	fmt.Fprintf(os.Stdout, "modified: %t\n", info.Modified)
	fmt.Fprintf(os.Stdout, "go: %s\n", info.GoVersion)
	return nil
}

func currentToolInfo() toolInfo {
	info := toolInfo{
		Name:      "hzn",
		Version:   buildVersion,
		Module:    modulePath,
		Commit:    buildCommit,
		BuiltAt:   buildDate,
		GoVersion: runtime.Version(),
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" || info.Version == "devel" {
			if build.Main.Version != "" && build.Main.Version != "(devel)" {
				info.Version = build.Main.Version
			}
		}
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.BuiltAt == "" {
					info.BuiltAt = setting.Value
				}
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "devel"
	}
	return info
}
