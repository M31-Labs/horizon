package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

func analyze(path string) (*compiler.Result, error) {
	result, err := compiler.AnalyzePath(path)
	if err != nil {
		return nil, err
	}
	if diag.HasErrors(result.Diagnostics) {
		for _, d := range result.Diagnostics {
			_, _ = os.Stderr.WriteString(d.Format() + "\n")
		}
		return nil, errDiagnostics(len(result.Diagnostics))
	}
	return result, nil
}

type errDiagnostics int

func (e errDiagnostics) Error() string {
	return fmt.Sprintf("%d diagnostic(s)", int(e))
}

func writeFile(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFile(path, data)
}

func outputBase(result *compiler.Result) string {
	if len(result.Files) == 0 {
		return "out"
	}
	base := filepath.Base(result.Files[0].Path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func sourceMapPath(cPath string) string {
	dir := filepath.Dir(cPath)
	base := filepath.Base(cPath)
	base = strings.TrimSuffix(base, ".bpf.c")
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return filepath.Join(dir, base+".hznmap.json")
}
