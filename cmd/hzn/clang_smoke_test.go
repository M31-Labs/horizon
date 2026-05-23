//go:build clang_smoke

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkbenchCompileSmoke(t *testing.T) {
	if _, err := os.Stat("/usr/local/include/vmlinux.h"); err != nil {
		t.Skipf("vmlinux.h not available: %v", err)
	}
	if err := run([]string{"doctor"}); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	outDir := t.TempDir()
	input := filepath.Join("..", "..", "examples", "execwatch")
	if err := run([]string{"workbench", input, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	for _, name := range []string{
		"exec.bpf.c",
		"exec.bpf.o",
		"exec.hznmap.json",
		"exec.bindings.go",
		"exec.cap.json",
		"exec.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}
