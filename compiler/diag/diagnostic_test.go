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

func TestAttachSourceContextAddsLineAndMarker(t *testing.T) {
	d := Diagnostic{
		Code:     "HZN2600",
		Severity: SeverityError,
		Message:  "packet header must be checked",
		Primary: span.Span{
			File:  "xdp.hzn",
			Start: span.Point{Line: 3, Column: 9},
			End:   span.Point{Line: 3, Column: 21},
		},
	}
	enriched := AttachSourceContexts([]Diagnostic{d}, map[span.FileID][]byte{
		"xdp.hzn": []byte("package probes\nfunc Drop() i32 {\n    tcp.dst_port\n}\n"),
	})
	if len(enriched) != 1 || enriched[0].Source == nil {
		t.Fatalf("source context = %#v, want one enriched diagnostic", enriched)
	}
	if enriched[0].Source.Line != 3 || enriched[0].Source.Column != 9 {
		t.Fatalf("source context = %#v, want line 3 column 9", enriched[0].Source)
	}
	if enriched[0].Source.Text != "    tcp.dst_port" {
		t.Fatalf("source text = %q", enriched[0].Source.Text)
	}
	if !strings.Contains(enriched[0].Source.Marker, "^^^^^^^^^^^^") {
		t.Fatalf("source marker = %q, want span marker", enriched[0].Source.Marker)
	}
	got := enriched[0].Format()
	if !strings.Contains(got, "3 |     tcp.dst_port") || !strings.Contains(got, "|         ^^^^^^^^^^^^") {
		t.Fatalf("formatted diagnostic missing source context:\n%s", got)
	}
}
