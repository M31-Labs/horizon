package verifier

import "m31labs.dev/horizon/compiler/span"

type Diagnostic struct {
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Span      span.Span `json:"span,omitempty"`
	Generated span.Span `json:"generated,omitempty"`
	Raw       string    `json:"raw,omitempty"`
}
