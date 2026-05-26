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
}
