package verifier

import "m31labs.dev/horizon/compiler/span"

type Diagnostic struct {
	Message string
	Span    span.Span
}
