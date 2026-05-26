package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/capability"
)

func TestCapabilitiesWritesManifestForExecwatch(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "exec.cap.json")
	if _, err := captureStdout(t, func() error {
		return run([]string{"capabilities", "../../examples/execwatch", "-o", outPath})
	}); err != nil {
		t.Fatalf("run capabilities: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest capability.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v\n%s", err, data)
	}

	if manifest.Schema == "" {
		t.Fatalf("manifest schema is empty: %#v", manifest)
	}
	if manifest.Package != "probes" {
		t.Fatalf("manifest package = %q, want %q", manifest.Package, "probes")
	}

	const wantName = "kernel.process.exec.observe"
	var found *capability.Capability
	for i, cap := range manifest.Capabilities {
		if cap.Name == wantName {
			found = &manifest.Capabilities[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("capability %q not found in manifest: %#v", wantName, manifest.Capabilities)
	}
	wantDanger := capability.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
	if found.Danger != wantDanger {
		t.Fatalf("capability %q danger = %+v, want %+v", wantName, found.Danger, wantDanger)
	}
	if found.Program != "OnExec" {
		t.Fatalf("capability %q program = %q, want %q", wantName, found.Program, "OnExec")
	}
}
