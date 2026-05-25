package capability

import (
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/internal/registry"
)

// TestRegistryMatchesNamespaceSwitch enforces that every (kind, attach)
// combination accepted by ExpectedKernelCapabilityPrefix matches an
// entry in the canonical registry. Drift fails CI — see
// spec.horizon-continuum-integration.v1 §A.3.
func TestRegistryMatchesNamespaceSwitch(t *testing.T) {
	r := registry.MustLoad()

	// Collect expected (kind, attach) -> prefix from the registry.
	expected := map[string]string{} // key = kind+"/"+attach, value = prefix+"."
	for _, ns := range r.Namespaces {
		prefix := ns.Namespace + "."
		if len(ns.AttachStrings) == 0 {
			// xdp shape: no attach string. Use empty attach.
			key := ns.AttachSurface + "/"
			expected[key] = prefix
			continue
		}
		for _, att := range ns.AttachStrings {
			key := ns.AttachSurface + "/" + att
			expected[key] = prefix
		}
	}

	// Probe every key with ExpectedKernelCapabilityPrefix and compare.
	for key, want := range expected {
		parts := strings.SplitN(key, "/", 2)
		kind, attach := parts[0], parts[1]
		got := ExpectedKernelCapabilityPrefix(kind, attach, "")
		if got != want {
			t.Errorf("ExpectedKernelCapabilityPrefix(%q, %q, \"\") = %q, registry says %q (registry entry missing or wrong in capability/namespace.go)", kind, attach, got, want)
		}
	}

	if t.Failed() {
		var keys []string
		for k := range expected {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Logf("registry covers: %v", keys)
	}
}
