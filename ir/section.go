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
	ProgramUprobe     ProgramKind = "uprobe"
	ProgramUretprobe  ProgramKind = "uretprobe"
	ProgramFentry     ProgramKind = "fentry"
	ProgramFexit      ProgramKind = "fexit"
)

type Section struct {
	Kind   ProgramKind
	Attach string
	Name   string
}
