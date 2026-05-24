package ir

type ProgramKind string

const (
	ProgramTracepoint ProgramKind = "tracepoint"
	ProgramXDP        ProgramKind = "xdp"
	ProgramTC         ProgramKind = "tc"
	ProgramCgroup     ProgramKind = "cgroup"
	ProgramLSM        ProgramKind = "lsm"
	ProgramKprobe     ProgramKind = "kprobe"
	ProgramKretprobe  ProgramKind = "kretprobe"
)

type Section struct {
	Kind   ProgramKind
	Attach string
	Name   string
}
