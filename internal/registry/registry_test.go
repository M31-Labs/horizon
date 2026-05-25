package registry

import "testing"

func TestLoadRegistry_PopulatesEntries(t *testing.T) {
	r := MustLoad()
	if r.Version != "1" {
		t.Fatalf("version = %q, want 1", r.Version)
	}
	if len(r.Namespaces) == 0 {
		t.Fatalf("no namespaces loaded")
	}
}

func TestLoadRegistry_KnownEntry(t *testing.T) {
	r := MustLoad()
	found := false
	for _, ns := range r.Namespaces {
		if ns.Namespace == "kernel.network.connect" && ns.AttachSurface == "cgroup" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing kernel.network.connect/cgroup entry")
	}
}
