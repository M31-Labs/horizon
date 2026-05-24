package clang

import (
	"slices"
	"testing"
)

func TestDefaultFlagsTreatWarningsAsErrors(t *testing.T) {
	flags := DefaultFlags()
	for _, want := range []string{"-target", "bpf", "-Wall", "-Wextra", "-Werror"} {
		if !slices.Contains(flags, want) {
			t.Fatalf("DefaultFlags() = %#v, want %s", flags, want)
		}
	}
}
