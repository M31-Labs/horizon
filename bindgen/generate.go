package bindgen

import (
	"fmt"

	"m31labs.dev/horizon/ir"
)

func Generate(program ir.Program, packageName string) (string, error) {
	if packageName == "" {
		packageName = "bindings"
	}
	return fmt.Sprintf("package %s\n", packageName), nil
}
