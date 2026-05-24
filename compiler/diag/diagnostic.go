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
	Span    span.Span `json:"span"`
	Message string    `json:"message"`
	Source  *Source   `json:"source,omitempty"`
}

type Diagnostic struct {
	Code     string    `json:"code,omitempty"`
	Severity Severity  `json:"severity"`
	Message  string    `json:"message"`
	Primary  span.Span `json:"primary,omitempty"`
	Labels   []Label   `json:"labels,omitempty"`
	Notes    []string  `json:"notes,omitempty"`
	Suggest  string    `json:"suggest,omitempty"`
	Source   *Source   `json:"source,omitempty"`
}

type Source struct {
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndColumn int    `json:"end_column,omitempty"`
	Text      string `json:"text"`
	Marker    string `json:"marker,omitempty"`
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
	if d.Source != nil && d.Source.Text != "" {
		fmt.Fprintf(&b, "\n  %4d | %s", d.Source.Line, d.Source.Text)
		if d.Source.Marker != "" {
			fmt.Fprintf(&b, "\n       | %s", d.Source.Marker)
		}
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
