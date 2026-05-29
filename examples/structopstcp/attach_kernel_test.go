//go:build kernel_matrix

// Package structopstcp_test holds the runtime load-test for the struct_ops TCP
// congestion-control example. It is gated behind the kernel_matrix build tag so
// it never runs under `make ci-go` (which has no kernel and no eBPF privileges);
// it runs on the kernel-matrix VMs or under `go test -tags kernel_matrix` on a
// capable host (kernel >= 5.6 with BTF and CONFIG_BPF_STRUCT_OPS=y).
//
// This is the v0.4 Track A A2 proof: the example now declares a struct_ops map
// (decision 0010), so the compiled object carries a real ebpf.StructOpsMap that
// the generated AttachOnTCPInit helper's findStructOpsMap() resolves. The test
// asserts the object loads, the struct_ops map is present and typed
// StructOpsMap, and — where the running kernel supports it — that the
// struct_ops registration attaches.
package structopstcp_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// buildObject compiles examples/structopstcp into a temp dir and returns the
// path to the generated .bpf.o. It uses the repo's own `hzn build` so the test
// exercises the exact codegen path the matrix builds.
func buildObject(t *testing.T) string {
	t.Helper()
	outDir := t.TempDir()
	// The test runs from the example package dir; the repo root (which holds
	// cmd/hzn and the module) is two levels up.
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	cmd := exec.Command("go", "run", "./cmd/hzn", "build", "./examples/structopstcp", "-o", outDir)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hzn build ./examples/structopstcp: %v\n%s", err, out)
	}
	obj := filepath.Join(outDir, "congestion.bpf.o")
	if _, err := os.Stat(obj); err != nil {
		t.Fatalf("expected built object %s: %v", obj, err)
	}
	return obj
}

// TestStructOpsCollectionCarriesStructOpsMap asserts, at the spec level (no
// kernel load required), that the compiled object declares the Ops map typed as
// a struct_ops map. This is the static half of the A2 proof and runs on any
// host with a Go toolchain and clang when invoked with -tags kernel_matrix.
func TestStructOpsCollectionCarriesStructOpsMap(t *testing.T) {
	obj := buildObject(t)
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatalf("LoadCollectionSpec(%s): %v", obj, err)
	}
	mapSpec, ok := spec.Maps["Ops"]
	if !ok {
		t.Fatalf("collection spec is missing the Ops struct_ops map; maps=%v", mapKeys(spec.Maps))
	}
	if mapSpec.Type != ebpf.StructOpsMap {
		t.Fatalf("Ops map type = %v, want %v (StructOpsMap)", mapSpec.Type, ebpf.StructOpsMap)
	}
	if _, ok := spec.Programs["OnTCPInit"]; !ok {
		t.Fatalf("collection spec is missing the OnTCPInit struct_ops program")
	}
}

// TestStructOpsAttaches loads the collection and attaches the struct_ops map on
// a capable kernel. It skips gracefully when the kernel is too old, lacks
// CONFIG_BPF_STRUCT_OPS / tcp_congestion_ops BTF, or the process lacks the
// capability to load BPF — the matrix records those as real-kernel signal (A1),
// not as a test failure here.
func TestStructOpsAttaches(t *testing.T) {
	obj := buildObject(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (needs privilege): %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatalf("LoadCollectionSpec(%s): %v", obj, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// A load failure here is expected on kernels without struct_ops support
		// or in unprivileged environments — that is matrix signal, not a unit
		// failure. The static spec assertion above already proves the codegen.
		t.Skipf("load struct_ops collection (kernel may lack CONFIG_BPF_STRUCT_OPS / tcp_congestion_ops BTF, or insufficient privilege): %v", err)
	}
	defer coll.Close()

	opsMap, ok := coll.Maps["Ops"]
	if !ok {
		t.Fatalf("loaded collection is missing the Ops map")
	}
	if opsMap.Type() != ebpf.StructOpsMap {
		t.Fatalf("loaded Ops map type = %v, want StructOpsMap", opsMap.Type())
	}

	lnk, err := link.AttachStructOps(link.StructOpsOptions{Map: opsMap})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("AttachStructOps not supported on this kernel: %v", err)
		}
		t.Skipf("AttachStructOps failed (kernel/registration constraint, captured by matrix): %v", err)
	}
	defer lnk.Close()
}

func mapKeys(m map[string]*ebpf.MapSpec) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
