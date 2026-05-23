package parser

import "testing"

func TestParseExecwatchPackage(t *testing.T) {
	file, err := ParsePath("../examples/execwatch/exec.hzn")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if file.Package != "probes" {
		t.Fatalf("package = %q, want probes", file.Package)
	}
}
