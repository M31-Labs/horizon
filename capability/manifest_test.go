package capability

import "testing"

func TestValidateManifest(t *testing.T) {
	m := NewManifest("probes")
	m.Capabilities = append(m.Capabilities, Capability{Name: "kernel.process.exec.observe", Kind: "source", Danger: "observe"})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
