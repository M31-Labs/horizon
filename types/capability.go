package types

import (
	"fmt"
	"strings"
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
// Mode describes what the program does at the syscall/event boundary.
// Scope describes where the impact lands.
// Reversibility describes how the effect outlasts the program.
type DangerAxes struct {
	Mode          string // observe | mutate | control
	Scope         string // event | process | network | filesystem | system
	Reversibility string // none | restart | persistent
}

// Axes maps a legacy flat DangerLevel to its canonical DangerAxes triple
// using the v0 → v1 migration table.
// Mirror at ir/capability.go::DangerLevel.Axes() — keep migration table in sync.
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

// ParseDangerAxes accepts either a legacy flat danger word ("observe",
// "mutate", "drop", "block", "privileged") or an explicit triple of the
// form "mode,scope,reversibility" (e.g. "control,network,restart").
// Both forms are validated against their respective allowlists.
func ParseDangerAxes(s string) (DangerAxes, error) {
	if s == "" {
		return DangerAxes{}, fmt.Errorf("danger string must not be empty")
	}
	if strings.ContainsRune(s, ',') {
		return parseDangerAxesTriple(s)
	}
	level := DangerLevel(s)
	switch level {
	case DangerObserve, DangerMutate, DangerDrop, DangerBlock, DangerPrivileged:
		return level.Axes(), nil
	default:
		return DangerAxes{}, fmt.Errorf("unrecognized danger %q: use one of observe, mutate, drop, block, privileged, or an explicit triple mode,scope,reversibility", s)
	}
}

func parseDangerAxesTriple(s string) (DangerAxes, error) {
	parts := strings.SplitN(s, ",", 3)
	if len(parts) != 3 {
		return DangerAxes{}, fmt.Errorf("danger triple %q must have exactly three comma-separated parts: mode,scope,reversibility", s)
	}
	mode, scope, rev := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	if !validDangerMode(mode) {
		return DangerAxes{}, fmt.Errorf("danger mode %q is not valid; use one of observe, mutate, control", mode)
	}
	if !validDangerScope(scope) {
		return DangerAxes{}, fmt.Errorf("danger scope %q is not valid; use one of event, process, network, filesystem, system", scope)
	}
	if !validDangerReversibility(rev) {
		return DangerAxes{}, fmt.Errorf("danger reversibility %q is not valid; use one of none, restart, persistent", rev)
	}
	return DangerAxes{Mode: mode, Scope: scope, Reversibility: rev}, nil
}

func validDangerMode(mode string) bool {
	switch mode {
	case "observe", "mutate", "control":
		return true
	default:
		return false
	}
}

func validDangerScope(scope string) bool {
	switch scope {
	case "event", "process", "network", "filesystem", "system":
		return true
	default:
		return false
	}
}

func validDangerReversibility(rev string) bool {
	switch rev {
	case "none", "restart", "persistent":
		return true
	default:
		return false
	}
}
