package ir

import "m31labs.dev/horizon/compiler/span"

type MapKind string

const (
	MapKindRingbuf MapKind = "ringbuf"
	MapKindHash    MapKind = "hash"
	MapKindArray   MapKind = "array"
)

type Map struct {
	Name       string
	Kind       MapKind
	Key        Type
	Val        Type
	MaxEntries string
	Span       span.Span
}
