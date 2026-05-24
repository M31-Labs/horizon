package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDoctorReadyWithRequiredWorkbenchDeps(t *testing.T) {
	binDir := t.TempDir()
	for _, name := range []string{"clang", "bpftool", "llvm-objdump", "llvm-strip"} {
		writeExecutable(t, filepath.Join(binDir, name))
	}
	includeDir := t.TempDir()
	bpfHeader := filepath.Join(includeDir, "bpf_helpers.h")
	coreHeader := filepath.Join(includeDir, "bpf_core_read.h")
	vmlinuxHeader := filepath.Join(includeDir, "vmlinux.h")
	btf := filepath.Join(includeDir, "btf.vmlinux")
	for _, path := range []string{bpfHeader, coreHeader, vmlinuxHeader, btf} {
		if err := os.WriteFile(path, []byte("ok\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	report := runDoctorChecks(doctorConfig{
		PathEnv:    binDir,
		BPFHeaders: []string{bpfHeader},
		CoreReadHeaders: []string{
			coreHeader,
		},
		VmlinuxHeaders: []string{vmlinuxHeader},
		BTFPath:        btf,
		AdditionalTools: []string{
			"bpftool",
			"llvm-objdump",
			"llvm-strip",
		},
		RunCommand: func(_ context.Context, _ string, _ []string, _ string) error {
			return nil
		},
	})
	if !report.Ready {
		t.Fatalf("ready = false, checks = %#v", report.Checks)
	}
}

func TestDoctorNotReadyWithoutVmlinuxHeader(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "clang"))
	includeDir := t.TempDir()
	bpfHeader := filepath.Join(includeDir, "bpf_helpers.h")
	coreHeader := filepath.Join(includeDir, "bpf_core_read.h")
	if err := os.WriteFile(bpfHeader, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write bpf header: %v", err)
	}
	if err := os.WriteFile(coreHeader, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write core header: %v", err)
	}

	report := runDoctorChecks(doctorConfig{
		PathEnv:         binDir,
		BPFHeaders:      []string{bpfHeader},
		CoreReadHeaders: []string{coreHeader},
		VmlinuxHeaders:  []string{filepath.Join(includeDir, "missing.h")},
		BTFPath:         filepath.Join(includeDir, "missing-btf"),
		RunCommand: func(_ context.Context, _ string, _ []string, _ string) error {
			return nil
		},
	})
	if report.Ready {
		t.Fatalf("ready = true, want false")
	}
}

func TestDoctorNotReadyWithoutCoreReadHeader(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "clang"))
	includeDir := t.TempDir()
	bpfHeader := filepath.Join(includeDir, "bpf_helpers.h")
	vmlinuxHeader := filepath.Join(includeDir, "vmlinux.h")
	if err := os.WriteFile(bpfHeader, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write bpf header: %v", err)
	}
	if err := os.WriteFile(vmlinuxHeader, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write vmlinux header: %v", err)
	}

	report := runDoctorChecks(doctorConfig{
		PathEnv:         binDir,
		BPFHeaders:      []string{bpfHeader},
		CoreReadHeaders: []string{filepath.Join(includeDir, "missing-bpf-core-read.h")},
		VmlinuxHeaders:  []string{vmlinuxHeader},
		BTFPath:         filepath.Join(includeDir, "missing-btf"),
		RunCommand: func(_ context.Context, _ string, _ []string, _ string) error {
			return nil
		},
	})
	if report.Ready {
		t.Fatalf("ready = true, want false")
	}
}

func TestDoctorRetriesTransientClangProbeFailure(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "clang"))
	includeDir := t.TempDir()
	bpfHeader := filepath.Join(includeDir, "bpf_helpers.h")
	coreHeader := filepath.Join(includeDir, "bpf_core_read.h")
	vmlinuxHeader := filepath.Join(includeDir, "vmlinux.h")
	for _, path := range []string{bpfHeader, coreHeader, vmlinuxHeader} {
		if err := os.WriteFile(path, []byte("ok\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	calls := 0
	report := runDoctorChecks(doctorConfig{
		PathEnv:              binDir,
		BPFHeaders:           []string{bpfHeader},
		CoreReadHeaders:      []string{coreHeader},
		VmlinuxHeaders:       []string{vmlinuxHeader},
		BTFPath:              filepath.Join(includeDir, "missing-btf"),
		ClangProbeAttempts:   2,
		ClangProbeRetryDelay: time.Nanosecond,
		RunCommand: func(_ context.Context, _ string, _ []string, _ string) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("signal: killed")
			}
			return nil
		},
	})
	if !report.Ready {
		t.Fatalf("ready = false after retry, checks = %#v", report.Checks)
	}
	if calls != 2 {
		t.Fatalf("clang probe calls = %d, want 2", calls)
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
