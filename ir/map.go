package ir

type MapKind string

const (
	MapKindRingbuf MapKind = "ringbuf"
	MapKindHash    MapKind = "hash"
	MapKindArray   MapKind = "array"
)

type Map struct {
	Name string
	Kind MapKind
	Key  Type
	Val  Type
}
