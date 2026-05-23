package verifier

import "m31labs.dev/horizon/ir"

func Remap(log Log, sourceMap ir.SourceMap) []Diagnostic {
	_ = sourceMap
	if log.Raw == "" {
		return nil
	}
	return []Diagnostic{{Message: log.Raw}}
}
