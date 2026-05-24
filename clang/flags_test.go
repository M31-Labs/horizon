package clang

import (
	"runtime"
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

func TestDefaultFlagsDefineHostTargetArchWhenKnown(t *testing.T) {
	define := TargetArchDefine(runtime.GOARCH)
	if define == "" {
		t.Skipf("no BPF target arch mapping for GOARCH=%s", runtime.GOARCH)
	}
	if want := "-D" + define; !slices.Contains(DefaultFlags(), want) {
		t.Fatalf("DefaultFlags() = %#v, want %s", DefaultFlags(), want)
	}
}

func TestTargetArchDefine(t *testing.T) {
	tests := map[string]string{
		"amd64":   "__TARGET_ARCH_x86",
		"386":     "__TARGET_ARCH_x86",
		"arm64":   "__TARGET_ARCH_arm64",
		"riscv64": "__TARGET_ARCH_riscv",
		"s390x":   "__TARGET_ARCH_s390",
		"unknown": "",
	}
	for goarch, want := range tests {
		if got := TargetArchDefine(goarch); got != want {
			t.Fatalf("TargetArchDefine(%q) = %q, want %q", goarch, got, want)
		}
	}
}
