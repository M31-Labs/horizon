package ir

type ProgramKind string

const (
	ProgramTracepoint ProgramKind = "tracepoint"
	ProgramXDP        ProgramKind = "xdp"
)

type Section struct {
	Kind   ProgramKind
	Attach string
	Name   string
}
