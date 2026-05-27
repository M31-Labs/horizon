package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

// jsonCheckEnvelope is the JSON-mode output shape of `hzn check -json`.
// v0.2 emitted a bare `[]diag.Diagnostic` at the top level; v0.3 wraps
// it so callers can discover the per-package manifest written alongside
// a successful check (#12 / ADR-0006). The shape change is a documented
// breaking change to the JSON CLI surface — the migration guide carries
// a [BREAKING] tag in the relevant section header. `manifest_path` is
// omitempty: absent when no per-package manifest was emitted (suppression
// via `-no-manifest`, zero capabilities, or pre-error exit).
type jsonCheckEnvelope struct {
	Diagnostics  []diag.Diagnostic `json:"diagnostics"`
	ManifestPath string            `json:"manifest_path,omitempty"`
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON diagnostics")
	manifestOut := fs.String("manifest-out", "", "override the per-package manifest output path")
	noManifest := fs.Bool("no-manifest", false, "suppress the per-package manifest side-artifact")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	result, err := compiler.CheckPath(pathArg(fs))
	if err != nil {
		return err
	}
	diagnostics := diagnosticsWithSourceContext(result.Diagnostics, result.Files)
	if !diag.HasErrors(diagnostics) {
		diagnostics = append(diagnostics, capabilityCoverageDiagnosticsForResult(result)...)
	}

	// Emit the per-package manifest only when the check itself is going
	// to pass — a failing build hasn't produced a trustworthy IR for
	// FromIR to consume. `emitPerPackageManifest` is otherwise no-op
	// safe: it returns "" without writing when suppressed, when the
	// package has zero capabilities, or when result.Files is empty.
	manifestPath := ""
	if !diag.HasErrors(diagnostics) {
		written, emitErr := emitPerPackageManifest(result, *manifestOut, *noManifest)
		if emitErr != nil {
			return emitErr
		}
		manifestPath = written
	}

	if *jsonOut {
		if diagnostics == nil {
			diagnostics = []diag.Diagnostic{}
		}
		env := jsonCheckEnvelope{Diagnostics: diagnostics, ManifestPath: manifestPath}
		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		if diag.HasErrors(diagnostics) {
			return fmt.Errorf("%d diagnostic(s)", len(diagnostics))
		}
		return nil
	}
	for _, d := range diagnostics {
		fmt.Println(d.Format())
	}
	if diag.HasErrors(diagnostics) {
		return fmt.Errorf("%d diagnostic(s)", len(diagnostics))
	}
	fmt.Printf("check passed: %d file(s)\n", len(result.Files))
	if manifestPath != "" {
		fmt.Printf("wrote per-package manifest: %s\n", manifestPath)
	}
	return nil
}

// emitPerPackageManifest writes a capability.Manifest for the just-checked
// package to disk and returns the path (relative to the process working
// directory, matching `relativeToCwd` in compiler/compile.go). Returns
// "" without writing when (a) suppress is true, (b) the program declares
// no capabilities (the artifact is a *capability* manifest, so an empty
// one carries no policy signal), or (c) result.Files is empty (defensive
// — should not happen on a passing check).
//
// Default output path: `<pkg-dir>/<package-name>.pkg.cap.json`, where
// `<pkg-dir>` is the directory holding the alphabetically-first .hzn
// file in result.Files (CollectFiles already sorts the slice, but a
// local sort makes the contract robust against future loader changes).
// The `.pkg` infix distinguishes this side-artifact from the
// single-rooted `<basename>.cap.json` emitted by `hzn capabilities`.
// When `program.Package` is empty (single-file invocations without a
// `package` declaration), fall back to the directory basename.
//
// Override path: when outPath is non-empty, write there instead.
// (#12 / ADR-0006.)
func emitPerPackageManifest(result *compiler.Result, outPath string, suppress bool) (string, error) {
	if suppress {
		return "", nil
	}
	if result == nil {
		return "", nil
	}
	if len(result.Program.Capabilities) == 0 {
		return "", nil
	}
	if len(result.Files) == 0 {
		return "", nil
	}

	target := outPath
	if target == "" {
		dir := perPackageManifestDir(result)
		name := result.Program.Package
		if name == "" {
			name = filepath.Base(dir)
		}
		target = filepath.Join(dir, name+".pkg.cap.json")
	}

	manifest := capability.FromIR(result.Program)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(target); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", err
	}
	return relativeToCwdOrPath(target), nil
}

// perPackageManifestDir returns the directory containing the
// alphabetically-first .hzn file in result.Files. compiler.CollectFiles
// already sorts the slice in lexical order, but a local sort keeps the
// "alphabetically-first" contract robust against future loader changes.
func perPackageManifestDir(result *compiler.Result) string {
	paths := make([]string, 0, len(result.Files))
	for _, f := range result.Files {
		if strings.HasSuffix(f.Path, ".hzn") {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return "."
	}
	return filepath.Dir(paths[0])
}

// relativeToCwdOrPath returns the given path relative to the process
// working directory when possible, falling back to the original path
// when relativization fails or escapes the cwd. Matches the convention
// established by compiler.relativeToCwd; reimplemented here to avoid
// exporting an internal helper.
func relativeToCwdOrPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, abs)
	if err != nil {
		return p
	}
	// Don't surface "../../tmp/..." style paths — fall back to the
	// absolute form when the target escapes the cwd. Test fixtures
	// using t.TempDir() rely on the absolute path being readable.
	if strings.HasPrefix(rel, "..") {
		return abs
	}
	return rel
}
