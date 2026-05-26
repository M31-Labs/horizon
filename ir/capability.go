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

// DangerAxes encodes capability danger as three orthogonal axes.
// This is additive alongside the existing DangerLevel flat string.
// Mode describes what the program does at the syscall/event boundary.
// Scope describes where the impact lands.
// Reversibility describes how the effect outlasts the program.
type DangerAxes struct {
	Mode          string // observe | mutate | control
	Scope         string // event | process | network | filesystem | system
	Reversibility string // none | restart | persistent
}

// Axes maps a DangerLevel to its canonical DangerAxes triple using the
// v0 → v1 migration table. Mirrors types.DangerLevel.Axes() to avoid a
// cross-package dependency on the types package from ir.
func (d DangerLevel) Axes() DangerAxes {
	switch d {
	case DangerObserve:
		return DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
	case DangerMutate:
		return DangerAxes{Mode: "mutate", Scope: "process", Reversibility: "restart"}
	case DangerDrop:
		return DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}
	case DangerBlock:
		return DangerAxes{Mode: "control", Scope: "process", Reversibility: "restart"}
	case DangerPrivileged:
		return DangerAxes{Mode: "mutate", Scope: "system", Reversibility: "persistent"}
	default:
		return DangerAxes{}
	}
}

type Capability struct {
	Name    string
	Kind    CapabilityKind
	Program string
	Section string
	Emits   string
	Maps    CapabilityMapAccess
	Danger  DangerLevel
	Axes    DangerAxes // additive: orthogonal axes alongside the flat Danger string
	Span    span.Span
	// Origin records the import alias of the dependency package this
	// capability was lowered from (roadmap #20 Phase 2 Subtask 4a). Root-
	// package capabilities have Origin == "". Aggregation (Task 5)
	// consumes Origin to emit qualified manifest names like
	// "events.ExecObserve".
	Origin string `json:",omitempty"`
}

type CapabilityMapAccess struct {
	Read   []string
	Write  []string
	Events []string
}
