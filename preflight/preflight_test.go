package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckReportsRungAndMissingPrerequisites(t *testing.T) {
	root := t.TempDir()
	writeProbe(t, root, "sys/kernel/btf/vmlinux", "btf")
	writeProbe(t, root, "sys/fs/cgroup/cgroup.controllers", "cpu memory")
	writeProbe(t, root, "sys/kernel/security/lsm", "lockdown,capability,bpf")
	writeProbe(t, root, "boot/config-6.12.0", "CONFIG_BPF_LSM=y\n")
	report := Check(Options{Root: root, KernelRelease: "6.12.0"})
	if !report.Ready() || report.EnforcementRung != "R1-bpf-lsm" || len(report.Issues) != 0 {
		t.Fatalf("ready report=%+v", report)
	}

	missing := Check(Options{Root: t.TempDir(), KernelRelease: "5.4.0"})
	if missing.Ready() || missing.EnforcementRung != "R0-lower-walls-only" || len(missing.Issues) < 4 {
		t.Fatalf("missing report=%+v", missing)
	}
}

func writeProbe(t *testing.T, root, path, content string) {
	t.Helper()
	name := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
