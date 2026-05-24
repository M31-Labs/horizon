package main

import (
	"encoding/json"
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
