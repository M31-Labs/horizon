package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/horizon/capability"
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

func TestDoctorReadyWithCapabilityManifestRequirements(t *testing.T) {
	mask := uint64(1)<<linuxCapBPF |
		uint64(1)<<linuxCapPerfmon |
		uint64(1)<<linuxCapNetAdmin |
		uint64(1)<<linuxCapSysAdmin
	report := runDoctorChecks(doctorManifestConfig(t, mask), capability.Manifest{
		Schema:       capability.SchemaV0,
		Package:      "probes",
		Capabilities: []capability.Capability{},
		Requirements: &capability.Requirements{
			MinKernel: "5.8",
			Permissions: []string{
				"bpf_program_load",
				"perf_event_open",
				"net_admin",
				"cgroup_admin",
				"lsm_admin",
			},
			Features: []string{
				"tracefs",
				"kprobes",
				"netdev_xdp",
				"tc_clsact",
				"cgroup_v2",
				"bpf_lsm",
			},
		},
	})
	if !report.Ready {
		t.Fatalf("ready = false, checks = %#v", report.Checks)
	}
	for _, name := range []string{
		"kernel >= 5.8",
		"permission bpf_program_load",
		"permission perf_event_open",
		"permission net_admin",
		"permission cgroup_admin",
		"permission lsm_admin",
		"host feature tracefs",
		"host feature kprobes",
		"host feature netdev_xdp",
		"host feature tc_clsact",
		"host feature cgroup_v2",
		"host feature bpf_lsm",
	} {
		requireDoctorCheck(t, report, name, "ok")
	}
}

func TestDoctorNotReadyWithUnsatisfiedCapabilityManifestRequirements(t *testing.T) {
	cfg := doctorManifestConfig(t, 0)
	cfg.KernelRelease = func() (string, error) { return "5.4.0-test", nil }
	cfg.CgroupControllers = filepath.Join(t.TempDir(), "missing-cgroup.controllers")

	report := runDoctorChecks(cfg, capability.Manifest{
		Schema:       capability.SchemaV0,
		Package:      "probes",
		Capabilities: []capability.Capability{},
		Requirements: &capability.Requirements{
			MinKernel:   "5.8",
			Permissions: []string{"net_admin"},
			Features:    []string{"cgroup_v2"},
		},
	})
	if report.Ready {
		t.Fatalf("ready = true, want false")
	}
	requireDoctorCheck(t, report, "kernel >= 5.8", "error")
	requireDoctorCheck(t, report, "permission net_admin", "error")
	requireDoctorCheck(t, report, "host feature cgroup_v2", "error")
}

func TestDoctorChecksPerCapabilityManifestRequirements(t *testing.T) {
	cfg := doctorManifestConfig(t, 0)
	cfg.KernelRelease = func() (string, error) { return "5.4.0-test", nil }
	cfg.TracefsPaths = []string{filepath.Join(t.TempDir(), "missing-tracefs")}

	report := runDoctorChecks(cfg, capability.Manifest{
		Schema:  capability.SchemaV0,
		Package: "probes",
		Capabilities: []capability.Capability{{
			Name:    "kernel.process.exec.observe",
			Kind:    "source",
			Danger:  capability.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
			Program: "OnExec",
			Section: "tracepoint/sched:sched_process_exec",
			Requirements: &capability.Requirements{
				Programs:    []capability.FeatureRequirement{{Name: "tracepoint", MinKernel: "4.7"}},
				Maps:        []capability.FeatureRequirement{{Name: "ringbuf", MinKernel: "5.8"}},
				Helpers:     []capability.FeatureRequirement{{Name: "bpf_ringbuf_reserve", MinKernel: "5.8"}},
				Permissions: []string{"bpf_program_load", "bpf_program_load"},
				Features:    []string{"tracefs", "tracefs"},
			},
		}},
	})
	if report.Ready {
		t.Fatalf("ready = true, want false for unsatisfied per-capability requirements")
	}
	requireDoctorCheck(t, report, "kernel >= 5.8", "error")
	requireDoctorCheck(t, report, "permission bpf_program_load", "error")
	requireDoctorCheck(t, report, "host feature tracefs", "error")
	if countDoctorChecks(report, "permission bpf_program_load") != 1 {
		t.Fatalf("checks = %#v, want permission requirement deduplicated", report.Checks)
	}
	if countDoctorChecks(report, "host feature tracefs") != 1 {
		t.Fatalf("checks = %#v, want feature requirement deduplicated", report.Checks)
	}
}

func TestDoctorReadsCapabilityManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exec.cap.json")
	manifest := capability.Manifest{
		Schema:       capability.SchemaV0,
		Package:      "probes",
		Capabilities: []capability.Capability{},
		Requirements: &capability.Requirements{
			MinKernel:   "5.8",
			Permissions: []string{"bpf_program_load"},
			Features:    []string{"tracefs"},
		},
	}
	if err := writeJSON(path, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	loaded, err := readDoctorCapabilityManifest(path)
	if err != nil {
		t.Fatalf("readDoctorCapabilityManifest: %v", err)
	}
	if loaded.Requirements == nil || loaded.Requirements.MinKernel != "5.8" {
		t.Fatalf("loaded manifest = %#v, want requirements", loaded)
	}
}

func doctorManifestConfig(t *testing.T, capabilityMask uint64) doctorConfig {
	t.Helper()
	binDir := t.TempDir()
	for _, name := range []string{"clang", "bpftool", "llvm-objdump", "llvm-strip", "tc"} {
		writeExecutable(t, filepath.Join(binDir, name))
	}
	includeDir := t.TempDir()
	bpfHeader := filepath.Join(includeDir, "bpf_helpers.h")
	coreHeader := filepath.Join(includeDir, "bpf_core_read.h")
	vmlinuxHeader := filepath.Join(includeDir, "vmlinux.h")
	btf := filepath.Join(includeDir, "btf.vmlinux")
	kprobeEvents := filepath.Join(includeDir, "kprobe_events")
	cgroupControllers := filepath.Join(includeDir, "cgroup.controllers")
	lsm := filepath.Join(includeDir, "lsm")
	procStatus := filepath.Join(includeDir, "status")
	for _, path := range []string{bpfHeader, coreHeader, vmlinuxHeader, btf, kprobeEvents, cgroupControllers} {
		if err := os.WriteFile(path, []byte("ok\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := os.WriteFile(lsm, []byte("lockdown,capability,bpf\n"), 0o644); err != nil {
		t.Fatalf("write lsm: %v", err)
	}
	if err := os.WriteFile(procStatus, []byte(fmt.Sprintf("CapEff:\t%016x\n", capabilityMask)), 0o644); err != nil {
		t.Fatalf("write proc status: %v", err)
	}
	return doctorConfig{
		PathEnv:         binDir,
		BPFHeaders:      []string{bpfHeader},
		CoreReadHeaders: []string{coreHeader},
		VmlinuxHeaders:  []string{vmlinuxHeader},
		BTFPath:         btf,
		AdditionalTools: []string{
			"bpftool",
			"llvm-objdump",
			"llvm-strip",
		},
		RunCommand: func(_ context.Context, _ string, _ []string, _ string) error {
			return nil
		},
		RuntimeGOOS:       "linux",
		KernelRelease:     func() (string, error) { return "6.8.0-test", nil },
		EffectiveUID:      func() int { return 1000 },
		ProcStatusPath:    procStatus,
		TracefsPaths:      []string{t.TempDir()},
		KprobeEventPaths:  []string{kprobeEvents},
		NetdevPath:        t.TempDir(),
		TCCommand:         "tc",
		CgroupControllers: cgroupControllers,
		LSMPath:           lsm,
	}
}

func requireDoctorCheck(t *testing.T, report doctorReport, name string, status string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			if check.Status != status {
				t.Fatalf("%s status = %q, want %q: %#v", name, check.Status, status, check)
			}
			return
		}
	}
	t.Fatalf("missing doctor check %q in %#v", name, report.Checks)
}

func countDoctorChecks(report doctorReport, name string) int {
	count := 0
	for _, check := range report.Checks {
		if check.Name == name {
			count++
		}
	}
	return count
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
