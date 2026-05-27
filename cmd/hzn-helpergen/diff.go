package main

import (
	"fmt"
	"sort"
	"strings"
)

// DiffRegistries produces a unified-diff-style textual description of
// how the right helper array deviates from the left. The empty string
// means the two arrays carry the same entries (matched by KernelSymbol)
// with identical Name / kernel_symbol fields.
//
// The diff is structural, not byte-level: re-ordering of array entries
// is NOT flagged (the on-disk registry is canonically alphabetical by
// Name; libbpf's header is sorted by helper id; comparing line-by-line
// would generate noise the operator must mentally strip out). What
// matters is membership and per-entry kernel_symbol identity.
//
// Diff lines:
//
//   - left-only: "- <kernel_symbol>            (Horizon name=<name>)"
//   - right-only: "+ <kernel_symbol>           (would-be name=<name>)"
//   - shape diff: "~ <kernel_symbol>           name: <left> -> <right>"
//
// Empty input on either side is fine — the result is a diff of "all
// entries added" or "all entries removed", same as comparing against
// the empty registry.
func DiffRegistries(left, right []RegistryHelper) string {
	leftByKernel := indexByKernelSymbol(left)
	rightByKernel := indexByKernelSymbol(right)

	allKernel := make([]string, 0, len(leftByKernel)+len(rightByKernel))
	seen := make(map[string]bool, len(leftByKernel)+len(rightByKernel))
	for k := range leftByKernel {
		if !seen[k] {
			allKernel = append(allKernel, k)
			seen[k] = true
		}
	}
	for k := range rightByKernel {
		if !seen[k] {
			allKernel = append(allKernel, k)
			seen[k] = true
		}
	}
	sort.Strings(allKernel)

	var lines []string
	for _, k := range allKernel {
		l, lok := leftByKernel[k]
		r, rok := rightByKernel[k]
		switch {
		case lok && !rok:
			lines = append(lines, fmt.Sprintf("- %s\t(Horizon name=%s)", k, l.Name))
		case !lok && rok:
			lines = append(lines, fmt.Sprintf("+ %s\t(would-be name=%s)", k, r.Name))
		case lok && rok:
			if l.Name != r.Name {
				lines = append(lines, fmt.Sprintf("~ %s\tname: %s -> %s", k, l.Name, r.Name))
			}
		}
	}

	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

func indexByKernelSymbol(entries []RegistryHelper) map[string]RegistryHelper {
	out := make(map[string]RegistryHelper, len(entries))
	for _, e := range entries {
		// Skip entries with empty KernelSymbol — defensive; the
		// loader would already have rejected them.
		if e.KernelSymbol == "" {
			continue
		}
		out[e.KernelSymbol] = e
	}
	return out
}
