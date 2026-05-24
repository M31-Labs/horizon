package capability

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
	Name         string        `json:"name"`
	Kind         string        `json:"kind"`
	Danger       string        `json:"danger"`
	Program      string        `json:"program"`
	Section      string        `json:"section"`
	Emits        string        `json:"emits,omitempty"`
	Maps         MapAccess     `json:"maps"`
	Requirements *Requirements `json:"requirements,omitempty"`
}

type MapAccess struct {
	Read   []string `json:"read"`
	Write  []string `json:"write"`
	Events []string `json:"events"`
}

type Map struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Key        string `json:"key,omitempty"`
	Value      string `json:"value,omitempty"`
	MaxEntries string `json:"max_entries,omitempty"`
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
		Schema:  SchemaV0,
		Package: packageName,
	}
}
