package compiler

import (
	"strings"
	"testing"
)

func TestBuildContextMatchesSimpleIdentifier(t *testing.T) {
	ctx := BuildContext{OS: "linux"}
	ok, err := ctx.Matches("linux")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if !ok {
		t.Fatalf("expected linux to match under OS=linux")
	}
}

func TestBuildContextMatchesNegation(t *testing.T) {
	ctx := BuildContext{OS: "linux", Arch: "amd64"}
	ok, err := ctx.Matches("!arm64")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if !ok {
		t.Fatalf("expected !arm64 to match under arch=amd64")
	}
}

func TestBuildContextMatchesConjunction(t *testing.T) {
	ctx := BuildContext{OS: "linux", Arch: "amd64"}
	ok, err := ctx.Matches("linux && amd64")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if !ok {
		t.Fatalf("expected linux && amd64 to match")
	}
	ok2, err := ctx.Matches("linux && arm64")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if ok2 {
		t.Fatalf("expected linux && arm64 to NOT match")
	}
}

func TestBuildContextMatchesDisjunction(t *testing.T) {
	cases := []struct {
		os   string
		want bool
	}{
		{"linux", true},
		{"darwin", true},
		{"windows", false},
	}
	for _, tc := range cases {
		ctx := BuildContext{OS: tc.os}
		ok, err := ctx.Matches("linux || darwin")
		if err != nil {
			t.Fatalf("matches: %v", err)
		}
		if ok != tc.want {
			t.Fatalf("os=%s: got %v want %v", tc.os, ok, tc.want)
		}
	}
}

func TestBuildContextMatchesKernelComparison(t *testing.T) {
	ctx := BuildContext{OS: "linux", Kernel: "5.15"}
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"kernel>=5.10", true},
		{"kernel>=5.15", true},
		{"kernel>=5.20", false},
		{"kernel<6.0", true},
		{"kernel<5.15", false},
		{"kernel==5.15", true},
		{"kernel==5.14", false},
		{"kernel>5.10", true},
		{"kernel>5.15", false},
		{"kernel<=5.15", true},
		{"kernel<=5.14", false},
	} {
		ok, err := ctx.Matches(tc.expr)
		if err != nil {
			t.Fatalf("matches %q: %v", tc.expr, err)
		}
		if ok != tc.want {
			t.Fatalf("%q against kernel=5.15: got %v want %v", tc.expr, ok, tc.want)
		}
	}
}

func TestBuildContextMatchesBTF(t *testing.T) {
	ctx := BuildContext{BTF: true}
	ok, err := ctx.Matches("btf")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if !ok {
		t.Fatalf("expected btf to match under BTF=true")
	}
	off := BuildContext{BTF: false}
	ok2, err := off.Matches("btf")
	if err != nil {
		t.Fatalf("matches: %v", err)
	}
	if ok2 {
		t.Fatalf("expected btf to NOT match under BTF=false")
	}
}

func TestBuildContextMatchesParenthesized(t *testing.T) {
	for _, tc := range []struct {
		ctx  BuildContext
		expr string
		want bool
	}{
		{BuildContext{OS: "linux", Arch: "amd64"}, "(linux || darwin) && !arm64", true},
		{BuildContext{OS: "linux", Arch: "arm64"}, "(linux || darwin) && !arm64", false},
		{BuildContext{OS: "darwin", Arch: "amd64"}, "(linux || darwin) && !arm64", true},
		{BuildContext{OS: "windows", Arch: "amd64"}, "(linux || darwin) && !arm64", false},
	} {
		ok, err := tc.ctx.Matches(tc.expr)
		if err != nil {
			t.Fatalf("matches %q ctx=%+v: %v", tc.expr, tc.ctx, err)
		}
		if ok != tc.want {
			t.Fatalf("%q ctx=%+v: got %v want %v", tc.expr, tc.ctx, ok, tc.want)
		}
	}
}

func TestBuildContextRejectsUnknownDimension(t *testing.T) {
	ctx := BuildContext{OS: "linux"}
	_, err := ctx.Matches("windows10")
	if err == nil {
		t.Fatalf("expected error for unknown dimension 'windows10'")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error should mention 'unknown': %v", err)
	}
}

// TestDetectContextHonorsEnvOverrides pins O-7's env-var override path —
// DetectContext reads HORIZON_BUILD_OS / _ARCH / _KERNEL / _BTF when set.
func TestDetectContextHonorsEnvOverrides(t *testing.T) {
	t.Setenv("HORIZON_BUILD_OS", "darwin")
	t.Setenv("HORIZON_BUILD_ARCH", "arm64")
	t.Setenv("HORIZON_BUILD_KERNEL", "6.1")
	t.Setenv("HORIZON_BUILD_BTF", "1")
	resetContextCache()
	t.Cleanup(resetContextCache)

	ctx := DetectContext()
	if ctx.OS != "darwin" || ctx.Arch != "arm64" || ctx.Kernel != "6.1" || !ctx.BTF {
		t.Fatalf("unexpected detected context: %+v", ctx)
	}
}

// TestDetectContextBTFEnvFalseDisables confirms HORIZON_BUILD_BTF=0
// suppresses BTF presence even if the file would otherwise be detectable.
func TestDetectContextBTFEnvFalseDisables(t *testing.T) {
	t.Setenv("HORIZON_BUILD_BTF", "0")
	resetContextCache()
	t.Cleanup(resetContextCache)

	ctx := DetectContext()
	if ctx.BTF {
		t.Fatalf("HORIZON_BUILD_BTF=0 should disable BTF; got ctx=%+v", ctx)
	}
}

// TestDetectContextCaches verifies O-7's sync.Once caching — repeated
// DetectContext calls return the same struct value.
func TestDetectContextCaches(t *testing.T) {
	// Ensure no env vars influence the result across the call (deterministic).
	t.Setenv("HORIZON_BUILD_OS", "linux")
	t.Setenv("HORIZON_BUILD_ARCH", "amd64")
	t.Setenv("HORIZON_BUILD_KERNEL", "5.15")
	t.Setenv("HORIZON_BUILD_BTF", "0")
	resetContextCache()
	t.Cleanup(resetContextCache)

	first := DetectContext()
	second := DetectContext()
	if first != second {
		t.Fatalf("DetectContext returned divergent values across calls: %+v vs %+v", first, second)
	}
}

// TestMatchesEmptyExpressionRejects pins that an empty expression is an
// error (callers ANDing zero directives should not invoke Matches at all).
func TestMatchesEmptyExpressionRejects(t *testing.T) {
	ctx := BuildContext{OS: "linux"}
	_, err := ctx.Matches("")
	if err == nil {
		t.Fatalf("expected error for empty expression")
	}
}

