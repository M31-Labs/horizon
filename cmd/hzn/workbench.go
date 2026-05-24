package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"m31labs.dev/horizon/bindgen"
	"m31labs.dev/horizon/capability"
	hclang "m31labs.dev/horizon/clang"
	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/emitc"
	"m31labs.dev/horizon/ir"
)

func runWorkbench(args []string) error {
	fs := flag.NewFlagSet("workbench", flag.ContinueOnError)
	outDir := fs.String("o", "dist", "output directory")
	packageName := fs.String("package", "bindings", "generated Go package name")
	compile := fs.Bool("compile", false, "also compile generated C to .bpf.o with clang")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := compiler.AnalyzePath(pathArg(fs))
	if err != nil {
		return err
	}
	report, err := writeWorkbenchArtifacts(result, workbenchOptions{
		OutDir:      *outDir,
		PackageName: *packageName,
		Compile:     *compile,
	})
	if *jsonOut && report.Schema != "" {
		if writeErr := writeJSON("", report); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		return err
	}
	if !*jsonOut {
		fmt.Printf("workbench %s: %d artifact(s)\n", report.Status, len(report.Artifacts))
	}
	if diag.HasErrors(result.Diagnostics) {
		if !*jsonOut {
			printDiagnostics(result.Diagnostics)
		}
		return errDiagnostics(len(result.Diagnostics))
	}
	return nil
}

type workbenchOptions struct {
	OutDir      string
	PackageName string
	Compile     bool
}

type workbenchReport struct {
	Schema          string            `json:"schema"`
	Package         string            `json:"package"`
	Sources         []sourceDetail    `json:"sources,omitempty"`
	Status          string            `json:"status"`
	Compile         bool              `json:"compile"`
	Artifacts       []string          `json:"artifacts"`
	ArtifactDetails []artifactDetail  `json:"artifact_details,omitempty"`
	Paths           artifactPaths     `json:"paths"`
	Diagnostics     []diag.Diagnostic `json:"diagnostics"`
	DiagnosticCount int               `json:"diagnostic_count"`
	Clang           string            `json:"clang,omitempty"`
}

type sourceDetail struct {
	Path    string `json:"path"`
	Package string `json:"package,omitempty"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type artifactDetail struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type artifactPaths struct {
	C            string `json:"c"`
	Object       string `json:"object,omitempty"`
	SourceMap    string `json:"source_map"`
	Bindings     string `json:"bindings"`
	Capabilities string `json:"capabilities"`
	Diagnostics  string `json:"diagnostics"`
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
	sources, err := collectSourceDetails(result.Files)
	if err != nil {
		return workbenchReport{}, err
	}
	report := workbenchReport{
		Schema:          "m31labs.dev/horizon/report/v0",
		Package:         result.Program.Package,
		Sources:         sources,
		Status:          "generated",
		Compile:         opts.Compile,
		Paths:           paths,
		Diagnostics:     diagnosticsForReport(result.Diagnostics),
		DiagnosticCount: len(result.Diagnostics),
	}
	if err := removeFileIfExists(paths.Object); err != nil {
		return report, err
	}
	if !opts.Compile {
		report.Paths.Object = ""
	}
	if diag.HasErrors(result.Diagnostics) {
		report.Status = "diagnostic_error"
		report.Artifacts = paths.diagnosticArtifacts()
		if err := writeJSON(paths.Diagnostics, report.Diagnostics); err != nil {
			return report, err
		}
		if err := addArtifactDetails(&report, paths); err != nil {
			return report, err
		}
		if err := writeJSON(paths.Report, report); err != nil {
			return report, err
		}
		return report, nil
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
	if err := writeJSON(paths.Diagnostics, report.Diagnostics); err != nil {
		return report, err
	}

	report.Artifacts = paths.artifacts(false)
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
			report.Diagnostics = append(report.Diagnostics, clangDiagnostics(report.Clang, cOutput.SourceMap, []byte(cOutput.Code))...)
			report.DiagnosticCount = len(report.Diagnostics)
			if writeErr := writeJSON(paths.Diagnostics, report.Diagnostics); writeErr != nil {
				return report, writeErr
			}
			if writeErr := addArtifactDetails(&report, paths); writeErr != nil {
				return report, writeErr
			}
			if writeErr := writeJSON(paths.Report, report); writeErr != nil {
				return report, writeErr
			}
			return report, err
		}
		report.Status = "ok"
		report.Artifacts = paths.artifacts(true)
	}
	if err := addArtifactDetails(&report, paths); err != nil {
		return report, err
	}
	if err := writeJSON(paths.Report, report); err != nil {
		return report, err
	}
	return report, nil
}

func collectSourceDetails(files []compiler.FileResult) ([]sourceDetail, error) {
	details := make([]sourceDetail, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		details = append(details, sourceDetail{
			Path:    file.Path,
			Package: file.Package,
			Size:    int64(len(data)),
			SHA256:  hex.EncodeToString(sum[:]),
		})
	}
	return details, nil
}

func artifactPathsFor(outDir string, base string) artifactPaths {
	return artifactPaths{
		C:            filepath.Join(outDir, base+".bpf.c"),
		Object:       filepath.Join(outDir, base+".bpf.o"),
		SourceMap:    filepath.Join(outDir, base+".hznmap.json"),
		Bindings:     filepath.Join(outDir, base+".bindings.go"),
		Capabilities: filepath.Join(outDir, base+".cap.json"),
		Diagnostics:  filepath.Join(outDir, base+".diagnostics.json"),
		Report:       filepath.Join(outDir, base+".report.json"),
	}
}

func (p artifactPaths) artifacts(includeObject bool) []string {
	out := []string{p.C}
	if includeObject {
		out = append(out, p.Object)
	}
	out = append(out, p.SourceMap, p.Bindings, p.Capabilities, p.Diagnostics, p.Report)
	return out
}

func (p artifactPaths) diagnosticArtifacts() []string {
	return []string{p.Diagnostics, p.Report}
}

func addArtifactDetails(report *workbenchReport, paths artifactPaths) error {
	details, err := collectArtifactDetails(report.Artifacts, paths)
	if err != nil {
		return err
	}
	report.ArtifactDetails = details
	return nil
}

func collectArtifactDetails(artifacts []string, paths artifactPaths) ([]artifactDetail, error) {
	details := make([]artifactDetail, 0, len(artifacts))
	for _, path := range artifacts {
		if path == "" || path == paths.Report {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		details = append(details, artifactDetail{
			Path:   path,
			Kind:   artifactKind(path, paths),
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return details, nil
}

func artifactKind(path string, paths artifactPaths) string {
	switch path {
	case paths.C:
		return "bpf_c"
	case paths.Object:
		return "bpf_object"
	case paths.SourceMap:
		return "source_map"
	case paths.Bindings:
		return "bindings"
	case paths.Capabilities:
		return "capabilities"
	case paths.Diagnostics:
		return "diagnostics"
	default:
		return "artifact"
	}
}

func removeFileIfExists(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func diagnosticsForReport(diags []diag.Diagnostic) []diag.Diagnostic {
	if diags == nil {
		return []diag.Diagnostic{}
	}
	return diags
}

func clangDiagnostics(raw string, sourceMap ir.SourceMap, generated []byte) []diag.Diagnostic {
	return diagnosticsFromVerifierLog(raw, sourceMap, generated)
}
