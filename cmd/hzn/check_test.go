package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
