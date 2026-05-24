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
		"exec.diagnostics.json",
		"exec.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}

func TestKprobeCompileSmoke(t *testing.T) {
	if _, err := os.Stat("/usr/local/include/vmlinux.h"); err != nil {
		t.Skipf("vmlinux.h not available: %v", err)
	}
	if err := run([]string{"doctor"}); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "open.hzn"), []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    bpf.current_pid()
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	for _, name := range []string{
		"open.bpf.c",
		"open.bpf.o",
		"open.hznmap.json",
		"open.bindings.go",
		"open.cap.json",
		"open.diagnostics.json",
		"open.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}
