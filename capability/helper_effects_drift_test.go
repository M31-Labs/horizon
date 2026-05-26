package capability

import (
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/internal/registry"
)

// compilerKnownHelperSurface enumerates every helper surface name the
// Horizon compiler currently recognizes. Two switches in
// capability/requirements.go drive this set:
//
//   - compilerHelperRequirements(name string) — six bpf.* intrinsics
//     (current_pid, current_ppid, current_uid, current_comm,
//     probe_read_user_str, ktime_get_ns).
//   - mapMethodHelper(method string) — six map / ringbuf methods
//     (lookup, update, delete, reserve, submit, discard). Map methods
//     materialize as surface names map.lookup / map.update / map.delete;
//     ringbuf methods as ringbuf.reserve / ringbuf.submit / ringbuf.discard.
//     The test asserts both directions of the mapping (the method label
//     resolves via mapMethodHelper, and the qualified surface name lives
//     in the registry).
//
// Adding a helper to either switch without updating this set is a
// build-breaking regression — that's the whole point of this test.
var compilerKnownHelperSurface = []string{
	"bpf.current_pid",
	"bpf.current_ppid",
	"bpf.current_uid",
	"bpf.current_comm",
	"bpf.ktime_get_ns",
	"bpf.probe_read_user_str",
	"ringbuf.reserve",
	"ringbuf.submit",
	"ringbuf.discard",
	"map.lookup",
	"map.update",
	"map.delete",
}

// TestRegistryCoversAllCompilerKnownHelpers asserts that the canonical
// compiler-known helper surface (the twelve names above) is exactly the
// registry's helper set. Drift in either direction is a hard failure.
func TestRegistryCoversAllCompilerKnownHelpers(t *testing.T) {
	want := append([]string(nil), compilerKnownHelperSurface...)
	sort.Strings(want)

	r := registry.MustLoadHelpers()
	got := make([]string, 0, len(r.Helpers))
	for _, h := range r.Helpers {
		got = append(got, h.Name)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("registry helper count = %d, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("registry vs compiler-known mismatch at %d: registry=%q compiler-known=%q\n got: %v\nwant: %v", i, got[i], want[i], got, want)
		}
	}
}

// TestCompilerHelperRequirementsResolvesEveryKnownBPFName asserts that
// every "bpf.*" entry in compilerKnownHelperSurface still resolves to a
// non-empty kernel-symbol list via compilerHelperRequirements. Deleting a
// case from the switch without removing the surface name here is a
// regression this test catches.
func TestCompilerHelperRequirementsResolvesEveryKnownBPFName(t *testing.T) {
	for _, name := range compilerKnownHelperSurface {
		if !strings.HasPrefix(name, "bpf.") {
			continue
		}
		syms := compilerHelperRequirements(name)
		if len(syms) == 0 {
			t.Errorf("compilerHelperRequirements(%q) returned no symbols — switch case missing or surface name drifted", name)
		}
	}
}

// TestMapMethodHelperResolvesEveryKnownMapAndRingbufMethod asserts that
// every "map.<method>" / "ringbuf.<method>" entry in
// compilerKnownHelperSurface still resolves via mapMethodHelper. Same
// regression-catching role as the bpf.* check above.
func TestMapMethodHelperResolvesEveryKnownMapAndRingbufMethod(t *testing.T) {
	for _, name := range compilerKnownHelperSurface {
		var method string
		switch {
		case strings.HasPrefix(name, "map."):
			method = strings.TrimPrefix(name, "map.")
		case strings.HasPrefix(name, "ringbuf."):
			method = strings.TrimPrefix(name, "ringbuf.")
		default:
			continue
		}
		if _, ok := mapMethodHelper(method); !ok {
			t.Errorf("mapMethodHelper(%q) returned !ok — switch case missing or surface name drifted (surface = %q)", method, name)
		}
	}
}
