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
	ProgramRawTP      ProgramKind = "raw_tp"
	ProgramSockOps    ProgramKind = "sockops"
	ProgramStructOps  ProgramKind = "struct_ops"
)

type Section struct {
	Kind   ProgramKind
	Attach string
	Name   string
}

// ManifestName returns the canonical section name string used in the
// capability manifest. For surfaces where the attach string is meaningful
// (kprobe, kretprobe, tracepoint, lsm, cgroup, tc, uprobe, uretprobe,
// fentry, fexit, raw_tp), the format is "<kind>/<attach>". For surfaces with
// no attach binding (xdp), the format is just the kind. Bare-section surfaces
// like uprobe use the same combined form in the manifest even though their
// emitted SEC(...) is bare — the manifest is the canonical contract for
// downstream consumers, distinct from the codegen-side SEC pin.
//
// This is the single source of truth for manifest section formatting.
// Both ir/build.go and capability/from_ir.go MUST route through it; any
// new attach surface added to the codebase automatically gets correct
// manifest formatting without coordinated edits in two places.
func (s Section) ManifestName() string {
	if s.Kind == ProgramTracepoint && s.Attach != "" {
		return "tracepoint/" + s.Attach
	}
	if s.Kind == ProgramXDP {
		return "xdp"
	}
	if s.Kind == ProgramTC {
		return "tc/" + s.Attach
	}
	if s.Kind == ProgramCgroup {
		return "cgroup/" + s.Attach
	}
	if s.Kind == ProgramLSM {
		return "lsm/" + s.Attach
	}
	if (s.Kind == ProgramKprobe || s.Kind == ProgramKretprobe) && s.Attach != "" {
		return string(s.Kind) + "/" + s.Attach
	}
	if (s.Kind == ProgramUprobe || s.Kind == ProgramUretprobe) && s.Attach != "" {
		return string(s.Kind) + "/" + s.Attach
	}
	if (s.Kind == ProgramFentry || s.Kind == ProgramFexit) && s.Attach != "" {
		return string(s.Kind) + "/" + s.Attach
	}
	if s.Kind == ProgramRawTP && s.Attach != "" {
		return string(s.Kind) + "/" + s.Attach
	}
	if s.Kind == ProgramStructOps && s.Attach != "" {
		return string(s.Kind) + "/" + s.Attach
	}
	return s.Name
}
