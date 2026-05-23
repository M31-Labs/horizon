package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	hclang "m31labs.dev/horizon/clang"
	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/emitc"
)

func runWorkbench(args []string) error {
	fs := flag.NewFlagSet("workbench", flag.ContinueOnError)
	outDir := fs.String("o", "dist", "output directory")
	packageName := fs.String("package", "bindings", "generated Go package name")
	compile := fs.Bool("compile", false, "also compile generated C to .bpf.o with clang")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	report, err := writeWorkbenchArtifacts(result, workbenchOptions{
		OutDir:      *outDir,
		PackageName: *packageName,
		Compile:     *compile,
	})
	if err != nil {
		return err
	}
	fmt.Printf("workbench %s: %d artifact(s)\n", report.Status, len(report.Artifacts))
	return nil
}

type workbenchOptions struct {
	OutDir      string
	PackageName string
	Compile     bool
}

type workbenchReport struct {
	Schema    string        `json:"schema"`
	Package   string        `json:"package"`
	Status    string        `json:"status"`
	Compile   bool          `json:"compile"`
	Artifacts []string      `json:"artifacts"`
	Paths     artifactPaths `json:"paths"`
	Clang     string        `json:"clang,omitempty"`
}

type artifactPaths struct {
	C            string `json:"c"`
	Object       string `json:"object,omitempty"`
	SourceMap    string `json:"source_map"`
	Bindings     string `json:"bindings"`
	Capabilities string `json:"capabilities"`
	Report       string `json:"report"`
}

func writeWorkbenchArtifacts(result *compiler.Result, opts workbenchOptions) (workbenchReport, error) {
	if opts.OutDir == "" {
		opts.OutDir = "dist"
	}
	if opts.PackageName == "" {
		opts.PackageName = "bindings"
	}
	paths := artifactPathsFor(opts.OutDir, outputBase(result))
	report := workbenchReport{
		Schema:  "m31labs.dev/horizon/report/v0",
		Package: result.Program.Package,
		Status:  "generated",
		Compile: opts.Compile,
		Paths:   paths,
	}
	if !opts.Compile {
		report.Paths.Object = ""
	}

	cOutput, err := emitc.Emit(result.Program)
	if err != nil {
		return report, err
	}
	cOutput.SourceMap.Generated.Path = paths.C
	if err := writeFile(paths.C, []byte(cOutput.Code)); err != nil {
		return report, err
	}
	if err := writeJSON(paths.SourceMap, cOutput.SourceMap); err != nil {
		return report, err
	}
	bindings, err := bindgen.Generate(result.Program, opts.PackageName)
	if err != nil {
		return report, err
	}
	if err := writeFile(paths.Bindings, []byte(bindings)); err != nil {
		return report, err
	}
	manifest := capability.FromIR(result.Program)
	if err := capability.Validate(manifest); err != nil {
		return report, err
	}
	if err := writeJSON(paths.Capabilities, manifest); err != nil {
		return report, err
	}

	report.Artifacts = paths.artifacts(opts.Compile)
	if opts.Compile {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := hclang.Compile(ctx, paths.C, paths.Object, hclang.Options{}); err != nil {
			report.Status = "clang_error"
			var clangErr *hclang.Error
			if errors.As(err, &clangErr) {
				report.Clang = clangErr.Output
			} else {
				report.Clang = err.Error()
			}
			if writeErr := writeJSON(paths.Report, report); writeErr != nil {
				return report, writeErr
			}
			return report, err
		}
		report.Status = "ok"
	}
	if err := writeJSON(paths.Report, report); err != nil {
		return report, err
	}
	return report, nil
}

func artifactPathsFor(outDir string, base string) artifactPaths {
	return artifactPaths{
		C:            filepath.Join(outDir, base+".bpf.c"),
		Object:       filepath.Join(outDir, base+".bpf.o"),
		SourceMap:    filepath.Join(outDir, base+".hznmap.json"),
		Bindings:     filepath.Join(outDir, base+".bindings.go"),
		Capabilities: filepath.Join(outDir, base+".cap.json"),
		Report:       filepath.Join(outDir, base+".report.json"),
	}
}

func (p artifactPaths) artifacts(includeObject bool) []string {
	out := []string{p.C}
	if includeObject {
		out = append(out, p.Object)
	}
	out = append(out, p.SourceMap, p.Bindings, p.Capabilities, p.Report)
	return out
}
