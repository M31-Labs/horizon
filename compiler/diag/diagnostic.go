package diag

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/compiler/span"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityNote    Severity = "note"
)

type Label struct {
	Span    span.Span
	Message string
}

type Diagnostic struct {
	Code     string
	Severity Severity
	Message  string
	Primary  span.Span
	Labels   []Label
	Notes    []string
	Suggest  string
}

func (d Diagnostic) HasPrimary() bool {
	return !d.Primary.IsZero()
}

func (d Diagnostic) Format() string {
	var b strings.Builder
	if d.Severity == "" {
		d.Severity = SeverityError
	}
	if d.Code == "" {
		fmt.Fprintf(&b, "%s: %s", d.Severity, d.Message)
	} else {
		fmt.Fprintf(&b, "%s[%s]: %s", d.Severity, d.Code, d.Message)
	}
	if d.HasPrimary() {
		fmt.Fprintf(&b, " --> %s:%d:%d", d.Primary.File, d.Primary.Start.Line, d.Primary.Start.Column)
	}
	for _, note := range d.Notes {
		if note != "" {
			fmt.Fprintf(&b, "\n  note: %s", note)
		}
	}
	if d.Suggest != "" {
		fmt.Fprintf(&b, "\n  help: %s", d.Suggest)
	}
	return b.String()
}

func HasErrors(diags []Diagnostic) bool {
	for _, d := range diags {
		if d.Severity == "" || d.Severity == SeverityError {
			return true
		}
	}
	return false
}
