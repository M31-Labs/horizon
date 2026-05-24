//go:build clang_smoke

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	clangSmokeDoctorOnce   sync.Once
	clangSmokeDoctorReport doctorReport
)

func requireClangSmoke(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/local/include/vmlinux.h"); err != nil {
		t.Skipf("vmlinux.h not available: %v", err)
	}
	clangSmokeDoctorOnce.Do(func() {
		clangSmokeDoctorReport = runDoctorChecks(defaultDoctorConfig())
	})
	if !clangSmokeDoctorReport.Ready {
		t.Fatalf("eBPF workbench dependencies are not ready:\n%s", formatDoctorProblems(clangSmokeDoctorReport))
	}
}

func formatDoctorProblems(report doctorReport) string {
	var b strings.Builder
	for _, check := range report.Checks {
		if check.Status == "ok" {
			continue
		}
		detail := check.Detail
		if detail == "" {
			detail = check.Path
		}
		fmt.Fprintf(&b, "[%s] %s", check.Status, check.Name)
		if detail != "" {
			fmt.Fprintf(&b, ": %s", detail)
		}
		if check.Suggest != "" {
			fmt.Fprintf(&b, "\n  help: %s", check.Suggest)
		}
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return "doctor reported not ready without a failing check"
	}
	return strings.TrimRight(b.String(), "\n")
}

func TestWorkbenchCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
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
	data, err := os.ReadFile(filepath.Join(outDir, "exec.report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report workbenchReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	assertArtifactDetail(t, report, "bpf_object")
}

func TestKprobeCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "open.hzn"), []byte(`package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const Negative i32 = -1

@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    dfd := i32(kprobe.arg1(ctx))
    if dfd < 0 {
        return 0
    }
    bpf.current_pid()
    return 0
}

@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    neg := -rc
    if neg < -1 {
        return Negative
    }
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

func TestTCCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "tc.hzn"), []byte(`package probes

@tc("ingress")
func PassIngress(ctx tc.Context) i32 {
    return tc.OK
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	for _, name := range []string{
		"tc.bpf.c",
		"tc.bpf.o",
		"tc.hznmap.json",
		"tc.bindings.go",
		"tc.cap.json",
		"tc.diagnostics.json",
		"tc.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}

func TestCgroupConnectCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "connect.hzn"), []byte(`package probes

@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.family(ctx) != cgroup.FamilyIPv4 {
        return cgroup.Allow
    }
    if cgroup.sock_type(ctx) != cgroup.SockStream {
        return cgroup.Allow
    }
    if cgroup.protocol(ctx) != cgroup.ProtocolTCP {
        return cgroup.Allow
    }
    if cgroup.src_ip4(ctx) == cgroup.ip4(0, 0, 0, 0) {
        return cgroup.Allow
    }
    if (cgroup.dst_port(ctx) == 25) && (cgroup.dst_ip4(ctx) != cgroup.ip4(127, 0, 0, 1)) {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	for _, name := range []string{
		"connect.bpf.c",
		"connect.bpf.o",
		"connect.hznmap.json",
		"connect.bindings.go",
		"connect.cap.json",
		"connect.diagnostics.json",
		"connect.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}

func TestLSMCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "lsm.hzn"), []byte(`package probes

@lsm("file_open")
func AllowFileOpen(ctx lsm.Context) i32 {
    return lsm.Allow
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	for _, name := range []string{
		"lsm.bpf.c",
		"lsm.bpf.o",
		"lsm.hznmap.json",
		"lsm.bindings.go",
		"lsm.cap.json",
		"lsm.diagnostics.json",
		"lsm.report.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing compiled artifact %s: %v", name, err)
		}
	}
}

func TestConstantSymbolCollisionCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "flags.hzn"), []byte(`package probes

const Enabled = true

type Flags struct {
    active bool
}

map FlagsByPID hash[u32, Flags]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    active := true
    if Enabled && active {
        if FlagsByPID.update(pid, Flags{active: active}) != 0 {
            return 0
        }
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "flags.bpf.c"))
	if err != nil {
		t.Fatalf("read generated C: %v", err)
	}
	if !strings.Contains(string(data), "hzn_const_Enabled") {
		t.Fatalf("generated C missing mangled constant name:\n%s", data)
	}
}

func TestConstBoundedLoopCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "loop.hzn"), []byte(`package probes

const MaxSamples u32 = 4

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    for i := 0; i < MaxSamples; i++ {
        bpf.current_pid()
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "loop.bpf.c"))
	if err != nil {
		t.Fatalf("read generated C: %v", err)
	}
	if !strings.Contains(string(data), "for (__u32 i = 0; i < hzn_const_MaxSamples; i++) {") {
		t.Fatalf("generated C missing typed const bounded loop:\n%s", data)
	}
}

func TestStructSymbolCollisionCompileSmoke(t *testing.T) {
	requireClangSmoke(t)
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "file.hzn"), []byte(`package probes

type file struct {
    pid u32
}

map Files hash[u32, file]

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Files.update(pid, file{pid: pid}) != 0 {
        return 0
    }
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	outDir := t.TempDir()
	if err := run([]string{"workbench", srcDir, "-o", outDir, "-compile"}); err != nil {
		t.Fatalf("workbench -compile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "file.bpf.c"))
	if err != nil {
		t.Fatalf("read generated C: %v", err)
	}
	code := string(data)
	if !strings.Contains(code, "struct hzn_type_file") {
		t.Fatalf("generated C missing mangled struct name:\n%s", data)
	}
	if strings.Contains(code, "struct file {") {
		t.Fatalf("generated C emitted colliding struct tag:\n%s", data)
	}
}
