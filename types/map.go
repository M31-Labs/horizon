package types

type MapKind string

const (
	MapRingbuf MapKind = "ringbuf"
	MapHash    MapKind = "hash"
	MapArray   MapKind = "array"
)
