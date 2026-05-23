package diag

import (
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/span"
)

func TestDiagnosticFormatIncludesLocation(t *testing.T) {
	d := Diagnostic{
		Code:     "HZN2001",
		Severity: SeverityError,
		Message:  "ringbuf reservation must be nil-checked before use",
		Primary: span.Span{
			File:  "exec.hzn",
			Start: span.Point{Line: 12, Column: 5},
		},
	}
	got := d.Format()
	if !strings.Contains(got, "error[HZN2001]") {
		t.Fatalf("missing code: %q", got)
	}
	if !strings.Contains(got, "exec.hzn:12:5") {
		t.Fatalf("missing location: %q", got)
	}
}
