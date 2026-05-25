package ir

import "m31labs.dev/horizon/compiler/span"

type CapabilityKind string

const (
	CapabilitySource CapabilityKind = "source"
)

type DangerLevel string

const (
	DangerObserve    DangerLevel = "observe"
	DangerMutate     DangerLevel = "mutate"
	DangerDrop       DangerLevel = "drop"
	DangerBlock      DangerLevel = "block"
	DangerPrivileged DangerLevel = "privileged"
)

type Capability struct {
	Name    string
	Kind    CapabilityKind
	Program string
	Section string
	Emits   string
	Maps    CapabilityMapAccess
	Danger  DangerLevel
	Span    span.Span
}

type CapabilityMapAccess struct {
	Read   []string
	Write  []string
	Events []string
}
