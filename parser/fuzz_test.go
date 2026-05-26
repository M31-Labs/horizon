package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/parser"
)

func FuzzParse(f *testing.F) {
	// Seed corpus from examples.
	matches, err := filepath.Glob("../examples/*/*.hzn")
	if err != nil {
		f.Fatalf("glob: %v", err)
	}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		f.Add(string(b))
	}

	f.Fuzz(func(t *testing.T, src string) {
		// Contract: parser must not panic on any input. Errors are fine.
		_, _ = parser.ParseSource(parser.SourceFile{
			Path:   "fuzz.hzn",
			Bytes:  []byte(src),
			FileID: span.FileID("fuzz.hzn"),
		})
	})
}
