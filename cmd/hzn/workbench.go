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
	"sort"
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
	preflight := fs.Bool("preflight", false, "run doctor checks against the generated capability manifest")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	clangTimeout := fs.Duration("clang-timeout", defaultClangTimeout(), "timeout for clang compilation (override with HZN_CLANG_TIMEOUT)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := compiler.AnalyzePath(pathArg(fs))
	if err != nil {
		return err
	}
	report, err := writeWorkbenchArtifacts(result, workbenchOptions{
		OutDir:       *outDir,
		PackageName:  *packageName,
		Compile:      *compile,
		Preflight:    *preflight,
		ClangTimeout: *clangTimeout,
	})
	if *jsonOut && report.Schema != "" {
		if writeErr := writeJSON("", report); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		if diag.HasErrors(report.Diagnostics) {
			if !*jsonOut {
				printDiagnostics(report.Diagnostics)
			}
			return errDiagnostics(report.DiagnosticCount)
		}
		return err
	}
	if !*jsonOut {
		fmt.Printf("workbench %s: %d artifact(s)\n", report.Status, len(report.Artifacts))
	}
	if diag.HasErrors(report.Diagnostics) {
		if !*jsonOut {
			printDiagnostics(report.Diagnostics)
		}
		return errDiagnostics(report.DiagnosticCount)
	}
	return nil
}

type workbenchOptions struct {
	OutDir       string
	PackageName  string
	Compile      bool
	Preflight    bool
	DoctorConfig *doctorConfig
	ClangTimeout time.Duration
}

const defaultClangTimeoutValue = 30 * time.Second

func defaultClangTimeout() time.Duration {
	if v := os.Getenv("HZN_CLANG_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultClangTimeoutValue
}

// resolveClangTimeout returns the duration to use for clang compilation.
// Zero or negative inputs fall back to defaultClangTimeoutValue so that an
// unset options struct does not produce an immediately-expired context.
func resolveClangTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultClangTimeoutValue
	}
	return d
}

func defaultWorkbenchOptions() workbenchOptions {
	return workbenchOptions{
		ClangTimeout: defaultClangTimeoutValue,
	}
}

type workbenchReport struct {
	Schema                string            `json:"schema"`
	Generator             string            `json:"generator"`
	Tool                  toolInfo          `json:"tool"`
	GeneratedAt           string            `json:"generated_at"`
	Package               string            `json:"package"`
	Sources               []sourceDetail    `json:"sources,omitempty"`
	Status                string            `json:"status"`
	Summary               workbenchSummary  `json:"summary"`
	Compile               bool              `json:"compile"`
	Artifacts             []string          `json:"artifacts"`
	ArtifactDetails       []artifactDetail  `json:"artifact_details,omitempty"`
	RemovedStaleArtifacts []string          `json:"removed_stale_artifacts,omitempty"`
	Paths                 artifactPaths     `json:"paths"`
	Diagnostics           []diag.Diagnostic `json:"diagnostics"`
	DiagnosticCount       int               `json:"diagnostic_count"`
	Clang                 string            `json:"clang,omitempty"`
	Preflight             *doctorReport     `json:"preflight,omitempty"`
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

type workbenchSummary struct {
	SourceCount       int      `json:"source_count"`
	ProgramCount      int      `json:"program_count"`
	MapCount          int      `json:"map_count"`
	CapabilityCount   int      `json:"capability_count"`
	TypeCount         int      `json:"type_count"`
	ProgramKinds      []string `json:"program_kinds,omitempty"`
	MapKinds          []string `json:"map_kinds,omitempty"`
	CapabilityDangers []string `json:"capability_dangers,omitempty"`
	MinKernel         string   `json:"min_kernel,omitempty"`
	Permissions       []string `json:"permissions,omitempty"`
	Features          []string `json:"features,omitempty"`
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
		Schema:      "m31labs.dev/horizon/report/v0",
		Generator:   "hzn workbench",
		Tool:        currentToolInfo(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Package:     result.Program.Package,
		Sources:     sources,
		Status:      "generated",
		Summary:     workbenchSummaryFor(result, sources),
		Compile:     opts.Compile,
		Paths:       paths,
		Diagnostics: diagnosticsForReport(result.Diagnostics, result.Files),
	}
	report.DiagnosticCount = len(report.Diagnostics)
	removed, err := removeStaleArtifacts(paths)
	if err != nil {
		return report, err
	}
	report.RemovedStaleArtifacts = removed
	if !opts.Compile {
		report.Paths.Object = ""
	}
	if diag.HasErrors(result.Diagnostics) {
		report.Summary.applyManifest(capability.FromIR(result.Program))
		report.Status = "diagnostic_error"
		report.Artifacts = paths.diagnosticArtifacts()
		if err := writeDiagnosticArtifacts(&report, paths); err != nil {
			return report, err
		}
		return report, nil
	}
	coverageDiagnostics := capabilityCoverageDiagnosticsForResult(result)
	if diag.HasErrors(coverageDiagnostics) {
		report.Diagnostics = append(report.Diagnostics, coverageDiagnostics...)
		report.DiagnosticCount = len(report.Diagnostics)
		report.Status = "diagnostic_error"
		report.Artifacts = paths.diagnosticArtifacts()
		if err := writeDiagnosticArtifacts(&report, paths); err != nil {
			return report, err
		}
		return report, nil
	}

	cOutput, err := emitc.Emit(result.Program)
	if err != nil {
		report.Summary.applyManifest(capability.FromIR(result.Program))
		if d, ok := emitc.DiagnosticForError(err); ok {
			report.Status = "emit_error"
			report.Diagnostics = append(report.Diagnostics, diagnosticsWithSourceContext([]diag.Diagnostic{d}, result.Files)...)
			report.DiagnosticCount = len(report.Diagnostics)
			report.Artifacts = paths.diagnosticArtifacts()
			if writeErr := writeJSON(paths.Diagnostics, report.Diagnostics); writeErr != nil {
				return report, writeErr
			}
			if writeErr := addArtifactDetails(&report, paths); writeErr != nil {
				return report, writeErr
			}
			if writeErr := writeJSON(paths.Report, report); writeErr != nil {
				return report, writeErr
			}
		}
		return report, err
	}
	manifest := capability.FromIR(result.Program)
	report.Summary.applyManifest(manifest)
	cOutput.SourceMap.Generated.Path = paths.C
	if err := writeFile(paths.C, []byte(cOutput.Code)); err != nil {
		return report, err
	}
	if err := writeJSON(paths.SourceMap, cOutput.SourceMap); err != nil {
		return report, err
	}
	bindings, err := bindgen.Generate(result.Program, opts.PackageName)
	if err != nil {
		if d, ok := bindgen.DiagnosticForError(err); ok {
			report.Status = "bindgen_error"
			report.Diagnostics = append(report.Diagnostics, diagnosticsWithSourceContext([]diag.Diagnostic{d}, result.Files)...)
			report.DiagnosticCount = len(report.Diagnostics)
			report.Artifacts = []string{paths.C, paths.SourceMap, paths.Diagnostics, paths.Report}
			if writeErr := writeJSON(paths.Diagnostics, report.Diagnostics); writeErr != nil {
				return report, writeErr
			}
			if writeErr := addArtifactDetails(&report, paths); writeErr != nil {
				return report, writeErr
			}
			if writeErr := writeJSON(paths.Report, report); writeErr != nil {
				return report, writeErr
			}
		}
		return report, err
	}
	if err := writeFile(paths.Bindings, []byte(bindings)); err != nil {
		return report, err
	}
	if err := capability.Validate(manifest); err != nil {
		if d, ok := capability.DiagnosticForError(err); ok {
			report.Status = "capability_error"
			report.Diagnostics = append(report.Diagnostics, diagnosticsWithSourceContext([]diag.Diagnostic{d}, result.Files)...)
			report.DiagnosticCount = len(report.Diagnostics)
			report.Artifacts = []string{paths.C, paths.SourceMap, paths.Bindings, paths.Diagnostics, paths.Report}
			if writeErr := writeJSON(paths.Diagnostics, report.Diagnostics); writeErr != nil {
				return report, writeErr
			}
			if writeErr := addArtifactDetails(&report, paths); writeErr != nil {
				return report, writeErr
			}
			if writeErr := writeJSON(paths.Report, report); writeErr != nil {
				return report, writeErr
			}
		}
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
		ctx, cancel := context.WithTimeout(context.Background(), resolveClangTimeout(opts.ClangTimeout))
		defer cancel()
		if err := hclang.Compile(ctx, paths.C, paths.Object, hclang.Options{}); err != nil {
			report.Status = "clang_error"
			var clangErr *hclang.Error
			if errors.As(err, &clangErr) {
				report.Clang = clangErr.Output
			} else {
				report.Clang = err.Error()
			}
			report.Diagnostics = append(report.Diagnostics, diagnosticsWithSourceContext(clangDiagnostics(report.Clang, cOutput.SourceMap, []byte(cOutput.Code)), result.Files)...)
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
	if err := applyWorkbenchPreflight(&report, opts, manifest); err != nil {
		if writeErr := addArtifactDetails(&report, paths); writeErr != nil {
			return report, writeErr
		}
		if writeErr := writeJSON(paths.Report, report); writeErr != nil {
			return report, writeErr
		}
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

func applyWorkbenchPreflight(report *workbenchReport, opts workbenchOptions, manifest capability.Manifest) error {
	if report == nil || !opts.Preflight {
		return nil
	}
	cfg := defaultDoctorConfig()
	if opts.DoctorConfig != nil {
		cfg = *opts.DoctorConfig
	}
	preflight := runDoctorChecks(cfg, manifest)
	report.Preflight = &preflight
	if !preflight.Ready {
		report.Status = "preflight_error"
		return fmt.Errorf("eBPF workbench preflight checks are not ready")
	}
	return nil
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

func writeDiagnosticArtifacts(report *workbenchReport, paths artifactPaths) error {
	if err := writeJSON(paths.Diagnostics, report.Diagnostics); err != nil {
		return err
	}
	if err := addArtifactDetails(report, paths); err != nil {
		return err
	}
	return writeJSON(paths.Report, report)
}

func workbenchSummaryFor(result *compiler.Result, sources []sourceDetail) workbenchSummary {
	if result == nil {
		return workbenchSummary{}
	}
	summary := workbenchSummary{
		SourceCount:     len(sources),
		ProgramCount:    workbenchProgramCount(result.Program),
		MapCount:        len(result.Program.Maps),
		CapabilityCount: len(result.Program.Capabilities),
		TypeCount:       len(result.Program.Structs),
	}
	programKinds := map[string]bool{}
	for _, fn := range result.Program.Functions {
		if fn.Section.Kind != "" {
			programKinds[string(fn.Section.Kind)] = true
		}
	}
	mapKinds := map[string]bool{}
	for _, m := range result.Program.Maps {
		if m.Kind != "" {
			mapKinds[string(m.Kind)] = true
		}
	}
	dangers := map[string]bool{}
	for _, cap := range result.Program.Capabilities {
		if cap.Danger != "" {
			dangers[string(cap.Danger)] = true
		}
	}
	summary.ProgramKinds = sortedKeys(programKinds)
	summary.MapKinds = sortedKeys(mapKinds)
	summary.CapabilityDangers = sortedKeys(dangers)
	return summary
}

func workbenchProgramCount(program ir.Program) int {
	count := 0
	for _, fn := range program.Functions {
		if fn.Section.Kind != "" {
			count++
		}
	}
	return count
}

func (s *workbenchSummary) applyManifest(manifest capability.Manifest) {
	if s == nil || manifest.Requirements == nil {
		return
	}
	s.MinKernel = manifest.Requirements.MinKernel
	s.Permissions = append([]string(nil), manifest.Requirements.Permissions...)
	s.Features = append([]string(nil), manifest.Requirements.Features...)
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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

func (p artifactPaths) allArtifacts() []string {
	return p.artifacts(true)
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

func removeStaleArtifacts(paths artifactPaths) ([]string, error) {
	var removed []string
	for _, path := range paths.allArtifacts() {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return removed, err
		}
		removed = append(removed, path)
	}
	return removed, nil
}

func diagnosticsForReport(diags []diag.Diagnostic, files []compiler.FileResult) []diag.Diagnostic {
	if diags == nil {
		return []diag.Diagnostic{}
	}
	return diagnosticsWithSourceContext(diags, files)
}

func clangDiagnostics(raw string, sourceMap ir.SourceMap, generated []byte) []diag.Diagnostic {
	return diagnosticsFromVerifierLog(raw, sourceMap, generated)
}
