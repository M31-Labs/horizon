package main

import (
	"testing"
	"time"
)

func TestClangTimeoutDefault(t *testing.T) {
	opts := defaultWorkbenchOptions()
	if opts.ClangTimeout != 30*time.Second {
		t.Fatalf("default ClangTimeout = %v, want 30s", opts.ClangTimeout)
	}
}

func TestClangTimeoutOverride(t *testing.T) {
	opts := defaultWorkbenchOptions()
	opts.ClangTimeout = 90 * time.Second
	if opts.ClangTimeout != 90*time.Second {
		t.Fatalf("override ClangTimeout = %v, want 90s", opts.ClangTimeout)
	}
}

// Precedence: env var overrides built-in default, but explicit flag wins over env.
// The flag's default is computed by defaultClangTimeout() which reads
// HZN_CLANG_TIMEOUT, so this test pins that behavior.
func TestClangTimeoutPrecedence(t *testing.T) {
	t.Setenv("HZN_CLANG_TIMEOUT", "45s")
	if got := defaultClangTimeout(); got != 45*time.Second {
		t.Fatalf("defaultClangTimeout with env = %v, want 45s", got)
	}
	t.Setenv("HZN_CLANG_TIMEOUT", "garbage")
	if got := defaultClangTimeout(); got != 30*time.Second {
		t.Fatalf("defaultClangTimeout with garbage env = %v, want 30s (fallback)", got)
	}
	t.Setenv("HZN_CLANG_TIMEOUT", "")
	if got := defaultClangTimeout(); got != defaultClangTimeoutValue {
		t.Fatalf("defaultClangTimeout with empty env = %v, want default", got)
	}
}

func TestResolveClangTimeoutClamp(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero clamps to default", 0, defaultClangTimeoutValue},
		{"negative clamps to default", -5 * time.Second, defaultClangTimeoutValue},
		{"positive passes through", 45 * time.Second, 45 * time.Second},
		{"one nanosecond passes through", time.Nanosecond, time.Nanosecond},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveClangTimeout(tc.in); got != tc.want {
				t.Fatalf("resolveClangTimeout(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
