package types

type ResourceState string

const (
	ResourceMaybeNil ResourceState = "maybe_nil"
	ResourceLive     ResourceState = "live"
	ResourceConsumed ResourceState = "consumed"
)
