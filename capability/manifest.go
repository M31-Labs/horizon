package capability

type Manifest struct {
	Schema       string       `json:"schema"`
	Package      string       `json:"package"`
	Programs     []Program    `json:"programs,omitempty"`
	Capabilities []Capability `json:"capabilities"`
	Maps         []Map        `json:"maps,omitempty"`
}

type Program struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Attach       string   `json:"attach"`
	Section      string   `json:"section"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type Capability struct {
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Danger  string    `json:"danger"`
	Program string    `json:"program"`
	Section string    `json:"section"`
	Emits   string    `json:"emits,omitempty"`
	Maps    MapAccess `json:"maps"`
}

type MapAccess struct {
	Read   []string `json:"read"`
	Write  []string `json:"write"`
	Events []string `json:"events"`
}

type Map struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

func NewManifest(packageName string) Manifest {
	return Manifest{
		Schema:  SchemaV0,
		Package: packageName,
	}
}
