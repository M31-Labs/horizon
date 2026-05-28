package types

import "testing"

// TestIsExportedRecognizesCapitalizedNames pins the Go-style first-rune
// rule that drives v0.3's cross-package privacy gate (roadmap #17).
func TestIsExportedRecognizesCapitalizedNames(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Foo", true},
		{"foo", false},
		{"FOO", true},
		{"Foo123", true},
		{"foo123", false},
		{"F", true},
		{"f", false},
		{"_foo", false},
		{"_Foo", false},
		{"123Foo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExported(tc.name); got != tc.want {
				t.Fatalf("isExported(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestIsExportedHandlesEmptyName pins the empty-string edge — empty names
// have no first rune to inspect; the safe default is unexported (a missing
// declaration name is a different error class, surfaced upstream).
func TestIsExportedHandlesEmptyName(t *testing.T) {
	if isExported("") {
		t.Fatal("isExported(\"\") = true, want false")
	}
}

// TestIsExportedHandlesUnicode pins that non-ASCII uppercase first runes
// count as exported. Horizon source is UTF-8 throughout; the privacy
// predicate must not silently downgrade non-ASCII names to package-private.
func TestIsExportedHandlesUnicode(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Ñame", true},  // Ñ is Lu (uppercase letter)
		{"ñame", false}, // ñ is Ll (lowercase letter)
		{"Über", true},  // Ü is Lu
		{"über", false}, // ü is Ll
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExported(tc.name); got != tc.want {
				t.Fatalf("isExported(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
