package main

import (
	"strings"
	"testing"
)

func TestDiffEmptyWhenIdentical(t *testing.T) {
	a := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
		{Name: "bpf.ktime_get_ns", KernelSymbol: "bpf_ktime_get_ns"},
	}
	b := []RegistryHelper{
		// Different ordering on purpose — diff is structural.
		{Name: "bpf.ktime_get_ns", KernelSymbol: "bpf_ktime_get_ns"},
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
	}
	if got := DiffRegistries(a, b); got != "" {
		t.Errorf("want empty diff for identical entries, got:\n%s", got)
	}
}

func TestDiffNonEmptyWhenHelperMissing(t *testing.T) {
	left := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
		{Name: "bpf.ktime_get_ns", KernelSymbol: "bpf_ktime_get_ns"},
	}
	right := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
	}
	got := DiffRegistries(left, right)
	if got == "" {
		t.Fatal("want non-empty diff when an entry is missing on the right, got empty")
	}
	if !strings.Contains(got, "- bpf_ktime_get_ns") {
		t.Errorf("want diff to flag bpf_ktime_get_ns as removed, got:\n%s", got)
	}
}

func TestDiffNonEmptyWhenKernelSymbolDiffers(t *testing.T) {
	// Two registries with the same surface Name but different
	// kernel_symbol — the indexer keys by kernel_symbol so this
	// surfaces as one removal + one addition.
	left := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
	}
	right := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_tgid_pid"},
	}
	got := DiffRegistries(left, right)
	if got == "" {
		t.Fatal("want non-empty diff when kernel_symbol differs, got empty")
	}
	if !strings.Contains(got, "- bpf_get_current_pid_tgid") {
		t.Errorf("want removal line for bpf_get_current_pid_tgid, got:\n%s", got)
	}
	if !strings.Contains(got, "+ bpf_get_current_tgid_pid") {
		t.Errorf("want addition line for bpf_get_current_tgid_pid, got:\n%s", got)
	}
}

func TestDiffNonEmptyWhenSurfaceNameDiffers(t *testing.T) {
	// Same kernel_symbol on both sides but different surface Name —
	// usually means an annotation rename. Should produce a "~" line.
	left := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
	}
	right := []RegistryHelper{
		{Name: "bpf.pid", KernelSymbol: "bpf_get_current_pid_tgid"},
	}
	got := DiffRegistries(left, right)
	if got == "" {
		t.Fatal("want non-empty diff when surface name differs, got empty")
	}
	if !strings.Contains(got, "~ bpf_get_current_pid_tgid") {
		t.Errorf("want rename marker for bpf_get_current_pid_tgid, got:\n%s", got)
	}
	if !strings.Contains(got, "bpf.current_pid -> bpf.pid") {
		t.Errorf("want name transition in diff line, got:\n%s", got)
	}
}

func TestDiffEmptyOnBothSides(t *testing.T) {
	if got := DiffRegistries(nil, nil); got != "" {
		t.Errorf("two empty registries should diff empty, got %q", got)
	}
}

func TestDiffAdditionsOnly(t *testing.T) {
	// Empty left, non-empty right: everything on the right is "+".
	right := []RegistryHelper{
		{Name: "bpf.current_pid", KernelSymbol: "bpf_get_current_pid_tgid"},
		{Name: "bpf.ktime_get_ns", KernelSymbol: "bpf_ktime_get_ns"},
	}
	got := DiffRegistries(nil, right)
	if got == "" {
		t.Fatal("want diff lines for additions against empty left, got empty")
	}
	if !strings.Contains(got, "+ bpf_get_current_pid_tgid") || !strings.Contains(got, "+ bpf_ktime_get_ns") {
		t.Errorf("want addition lines for both entries, got:\n%s", got)
	}
}
