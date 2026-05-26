package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func TestCheckJSONIncludesSourceContext(t *testing.T) {
	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", "../../testdata/invalid/packet_unproven_read.hzn", "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want diagnostics error")
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) == 0 {
		t.Fatal("diagnostics = 0, want source-aware diagnostic")
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, "ip.protocol") {
		t.Fatalf("source context = %#v, want authored packet line", diagnostics[0].Source)
	}
	if diagnostics[0].Source.Marker == "" {
		t.Fatalf("source marker is empty for %#v", diagnostics[0].Source)
	}
}

func TestCheckRejectsProgramWithoutCapabilityCoverage(t *testing.T) {
	input := filepath.Join(t.TempDir(), "nocap.hzn")
	if err := os.WriteFile(input, []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", input, "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want missing capability diagnostic")
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "HZN3301" {
		t.Fatalf("diagnostics = %#v, want HZN3301", diagnostics)
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, `@tracepoint("sched:sched_process_exec")`) {
		t.Fatalf("source context = %#v, want section attribute line", diagnostics[0].Source)
	}
}

func TestCheckCapabilityNamespaceMismatchPointsAtCapability(t *testing.T) {
	input := filepath.Join(t.TempDir(), "wrongcap.hzn")
	if err := os.WriteFile(input, []byte(`package probes

@capability("kernel.process.exec.observe")
@xdp
func DropTCP(ctx xdp.Context) i32 {
    return xdp.Pass
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"check", input, "-json"})
	})
	if err == nil {
		t.Fatal("run check -json succeeded, want capability namespace diagnostic")
	}
	var diagnostics []diag.Diagnostic
	if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
		t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "HZN2502" {
		t.Fatalf("diagnostics = %#v, want HZN2502", diagnostics)
	}
	if diagnostics[0].Source == nil || !strings.Contains(diagnostics[0].Source.Text, `@capability("kernel.process.exec.observe")`) {
		t.Fatalf("source context = %#v, want capability attribute line", diagnostics[0].Source)
	}
}

// TestCheckPinsCrossPackageFailureModes verifies that the four conflict-case
// fixtures landed in Phase 2 Subtask 6c each surface their expected
// diagnostic code when fed through `hzn check`. The fixtures live under
// testdata/invalid/import-*/ and testdata/invalid/capability-value-conflict/
// (plus testdata/invalid/import-not-found.hzn for the single-file case).
//
//   - import-not-found.hzn → HZN1554 (unresolved import path)
//   - import-cycle/         → HZN1555 (import cycle detected by the
//     resolver's DFS visited-set)
//   - import-alias-conflict/ → HZN1004 (extended) when an import alias
//     shadows a hardcoded compiler namespace such as `bpf`, `xdp`, etc.
//   - capability-value-conflict/ → HZN1553 (the aggregator-level advisory
//     when two packages contribute capabilities with the same value
//     string under different qualified names). HZN1560 is reserved for
//     same-qualified-name cross-package conflicts; that path is currently
//     defensive because upstream type-check (HZN1002) and validate
//     (HZN2503) catch the natural triggers first. This fixture pins the
//     aggregator code that is actually reachable through AnalyzePath
//     today.
func TestCheckPinsCrossPackageFailureModes(t *testing.T) {
	cases := []struct {
		path string
		code string
	}{
		{"../../testdata/invalid/import-not-found.hzn", "HZN1554"},
		{"../../testdata/invalid/import-cycle", "HZN1555"},
		{"../../testdata/invalid/import-alias-conflict", "HZN1004"},
		{"../../testdata/invalid/capability-value-conflict", "HZN1553"},
	}
	for _, tc := range cases {
		t.Run(tc.code+"/"+filepath.Base(tc.path), func(t *testing.T) {
			stdout, _ := captureStdout(t, func() error {
				return run([]string{"check", tc.path, "-json"})
			})
			var diagnostics []diag.Diagnostic
			if err := json.Unmarshal([]byte(stdout), &diagnostics); err != nil {
				t.Fatalf("unmarshal diagnostics: %v\n%s", err, stdout)
			}
			if !slices.ContainsFunc(diagnostics, func(d diag.Diagnostic) bool {
				return d.Code == tc.code
			}) {
				t.Fatalf("check %s diagnostics = %#v, want code %s", tc.path, diagnostics, tc.code)
			}
		})
	}
}
