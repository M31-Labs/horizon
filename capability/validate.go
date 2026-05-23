package capability

import "fmt"

func Validate(m Manifest) error {
	if m.Schema == "" {
		return fmt.Errorf("capability manifest schema is required")
	}
	if m.Schema != SchemaV0 {
		return fmt.Errorf("unsupported capability manifest schema %q", m.Schema)
	}
	if m.Package == "" {
		return fmt.Errorf("capability manifest package is required")
	}
	return nil
}
