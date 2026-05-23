package main

import (
	"context"
	"errors"
	"flag"
	"path/filepath"
	"time"

	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	hclang "m31labs.dev/horizon/clang"
	"m31labs.dev/horizon/emitc"
)

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	outDir := fs.String("o", "dist", "output directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := analyze(pathArg(fs))
	if err != nil {
		return err
	}
	base := outputBase(result)
	cPath := filepath.Join(*outDir, base+".bpf.c")
	objPath := filepath.Join(*outDir, base+".bpf.o")
	mapPath := filepath.Join(*outDir, base+".hznmap.json")
	bindPath := filepath.Join(*outDir, base+".bindings.go")
	capPath := filepath.Join(*outDir, base+".cap.json")
	reportPath := filepath.Join(*outDir, base+".report.json")

	cOutput, err := emitc.Emit(result.Program)
	if err != nil {
		return err
	}
	cOutput.SourceMap.Generated.Path = cPath
	if err := writeFile(cPath, []byte(cOutput.Code)); err != nil {
		return err
	}
	if err := writeJSON(mapPath, cOutput.SourceMap); err != nil {
		return err
	}
	bindings, err := bindgen.Generate(result.Program, "bindings")
	if err != nil {
		return err
	}
	if err := writeFile(bindPath, []byte(bindings)); err != nil {
		return err
	}
	manifest := capability.FromIR(result.Program)
	if err := capability.Validate(manifest); err != nil {
		return err
	}
	if err := writeJSON(capPath, manifest); err != nil {
		return err
	}

	report := buildReport{
		Package:   result.Program.Package,
		Artifacts: []string{cPath, objPath, mapPath, bindPath, capPath, reportPath},
		Status:    "ok",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := hclang.Compile(ctx, cPath, objPath, hclang.Options{}); err != nil {
		report.Status = "clang_error"
		var clangErr *hclang.Error
		if errors.As(err, &clangErr) {
			report.Clang = clangErr.Output
		} else {
			report.Clang = err.Error()
		}
		if writeErr := writeJSON(reportPath, report); writeErr != nil {
			return writeErr
		}
		return err
	}
	return writeJSON(reportPath, report)
}

type buildReport struct {
	Package   string   `json:"package"`
	Status    string   `json:"status"`
	Artifacts []string `json:"artifacts"`
	Clang     string   `json:"clang,omitempty"`
}
