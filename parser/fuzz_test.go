package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/parser"
)

func FuzzParse(f *testing.F) {
	// Seed corpus from examples and from testdata fixtures (including hand-crafted
	// invalid sources which are great fuzz seeds — they're already near parser
	// boundaries).
	patterns := []string{
		"../examples/*/*.hzn",
		"../testdata/invalid/*.hzn",
		"../testdata/golden/*/*.hzn",
	}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			f.Fatalf("glob %s: %v", pat, err)
		}
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			f.Add(string(b))
		}
	}

	f.Fuzz(func(t *testing.T, src string) {
		// Contract is intentionally panic-only for v0.2: any deeper invariants
		// (e.g., non-nil AST on success) belong in unit tests, not fuzz tests.
		_, _ = parser.ParseSource(parser.SourceFile{
			Path:   "fuzz.hzn",
			Bytes:  []byte(src),
			FileID: span.FileID("fuzz.hzn"),
		})
	})
}
