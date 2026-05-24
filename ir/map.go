package ir

import "m31labs.dev/horizon/compiler/span"

type MapKind string

const (
	MapKindRingbuf     MapKind = "ringbuf"
	MapKindHash        MapKind = "hash"
	MapKindArray       MapKind = "array"
	MapKindPerCPUHash  MapKind = "percpu_hash"
	MapKindPerCPUArray MapKind = "percpu_array"
	MapKindLRUHash     MapKind = "lru_hash"
	MapKindLRUPerCPU   MapKind = "lru_percpu_hash"
)

func (k MapKind) IsLookup() bool {
	return k.IsHashLike() || k.IsArrayLike()
}

func (k MapKind) IsHashLike() bool {
	return k == MapKindHash || k == MapKindPerCPUHash || k == MapKindLRUHash || k == MapKindLRUPerCPU
}

func (k MapKind) IsArrayLike() bool {
	return k == MapKindArray || k == MapKindPerCPUArray
}

func (k MapKind) HasPerCPUValue() bool {
	return k == MapKindPerCPUHash || k == MapKindPerCPUArray || k == MapKindLRUPerCPU
}

type Map struct {
	Name       string
	Kind       MapKind
	Key        Type
	Val        Type
	MaxEntries string
	Span       span.Span
}
