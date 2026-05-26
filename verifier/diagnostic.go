package verifier

import "m31labs.dev/horizon/compiler/span"

type Diagnostic struct {
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Span      span.Span `json:"span,omitempty"`
	Generated span.Span `json:"generated,omitempty"`
	Function  string    `json:"function,omitempty"`
	Section   string    `json:"section,omitempty"`
	Node      string    `json:"node,omitempty"`
	Mapping   string    `json:"mapping,omitempty"`
	Raw       string    `json:"raw,omitempty"`
	// Kind mirrors LogEntry.Kind: "clang_diagnostic" for clang-rooted
	// entries, "verifier" for verifier-rooted entries, and empty for
	// synthetic fallback diagnostics produced when ParseLog yields no
	// entries. Used by the diagnose path to gate the verifier-message
	// catalog (roadmap #14, plan Task 5.4).
	Kind string `json:"kind,omitempty"`
}
