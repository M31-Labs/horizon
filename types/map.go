package types

type MapKind string

const (
	MapRingbuf     MapKind = "ringbuf"
	MapHash        MapKind = "hash"
	MapArray       MapKind = "array"
	MapPerCPUHash  MapKind = "percpu_hash"
	MapPerCPUArray MapKind = "percpu_array"
	MapLRUHash     MapKind = "lru_hash"
	MapLRUPerCPU   MapKind = "lru_percpu_hash"
)
