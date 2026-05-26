package capability

// DangerAxes encodes capability danger as three orthogonal axes:
// - Mode: what the program does at the syscall/event boundary (observe | mutate | control)
// - Scope: what the impact lands on (event | process | network | filesystem | system)
// - Reversibility: how the effect outlasts the program (none | restart | persistent)
type DangerAxes struct {
	Mode          string `json:"mode"`
	Scope         string `json:"scope"`
	Reversibility string `json:"reversibility"`
}

// String returns a compact "mode,scope,reversibility" representation.
func (d DangerAxes) String() string {
	return d.Mode + "," + d.Scope + "," + d.Reversibility
}

// IsZero reports whether the axes are the zero value (all empty strings).
func (d DangerAxes) IsZero() bool {
	return d.Mode == "" && d.Scope == "" && d.Reversibility == ""
}

type Manifest struct {
	Schema       string        `json:"schema"`
	Package      string        `json:"package"`
	Programs     []Program     `json:"programs,omitempty"`
	Capabilities []Capability  `json:"capabilities"`
	Maps         []Map         `json:"maps,omitempty"`
	Types        []TypeSchema  `json:"types,omitempty"`
	Requirements *Requirements `json:"requirements,omitempty"`
}

type Program struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Attach       string   `json:"attach"`
	Section      string   `json:"section"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type Capability struct {
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Danger        DangerAxes     `json:"danger"`
	Program       string         `json:"program"`
	Section       string         `json:"section"`
	Emits         string         `json:"emits,omitempty"`
	Maps          MapAccess      `json:"maps"`
	Requirements  *Requirements  `json:"requirements,omitempty"`
	HelperEffects []HelperEffect `json:"helper_effects,omitempty"`
}

type MapAccess struct {
	Read   []string `json:"read"`
	Write  []string `json:"write"`
	Events []string `json:"events"`
}

type Map struct {
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Key                string `json:"key,omitempty"`
	Value              string `json:"value,omitempty"`
	MaxEntries         string `json:"max_entries,omitempty"`
	SteadyStateEntries string `json:"steady_state_entries,omitempty"`
	AccessFreq         string `json:"access_freq,omitempty"`
}

type TypeSchema struct {
	Name   string        `json:"name"`
	Kind   string        `json:"kind"`
	Size   *int          `json:"size,omitempty"`
	Align  *int          `json:"align,omitempty"`
	Fields []FieldSchema `json:"fields,omitempty"`
}

type FieldSchema struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset *int   `json:"offset,omitempty"`
}

type Requirements struct {
	MinKernel   string               `json:"min_kernel,omitempty"`
	Programs    []FeatureRequirement `json:"programs,omitempty"`
	Maps        []FeatureRequirement `json:"maps,omitempty"`
	Helpers     []FeatureRequirement `json:"helpers,omitempty"`
	Permissions []string             `json:"permissions,omitempty"`
	Features    []string             `json:"features,omitempty"`
}

type FeatureRequirement struct {
	Name      string `json:"name"`
	MinKernel string `json:"min_kernel"`
}

func NewManifest(packageName string) Manifest {
	return Manifest{
		Schema:       SchemaV1,
		Package:      packageName,
		Capabilities: []Capability{},
	}
}
