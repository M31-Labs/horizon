package ir

type ProgramKind string

const (
	ProgramTracepoint ProgramKind = "tracepoint"
)

type Section struct {
	Kind   ProgramKind
	Attach string
	Name   string
}
