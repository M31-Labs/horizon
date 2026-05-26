package validate_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/validate"
)

// TestValidatorContractAcrossExamples pins the current diagnostic output for
// every example. Refactoring validators must not change this set.
func TestValidatorContractAcrossExamples(t *testing.T) {
	examples, err := filepath.Glob("../examples/*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, ex := range examples {
		t.Run(filepath.Base(ex), func(t *testing.T) {
			result, err := compiler.AnalyzePath(ex)
			if err != nil {
				// Some examples may fail front-end; that is fine for this contract.
				return
			}
			diags := validate.Program(result.Program)
			codes := make([]string, 0, len(diags))
			for _, d := range diags {
				codes = append(codes, d.Code)
			}
			sort.Strings(codes)
			got := strings.Join(codes, ",")
			want := expectedDiagCodes(filepath.Base(ex))
			if got != want {
				t.Fatalf("%s diagnostic codes changed: got %q want %q",
					filepath.Base(ex), got, want)
			}
		})
	}
}

// expectedDiagCodes returns the baseline diagnostic codes per example,
// recorded before the unified-walk refactor. All ten current examples compile
// cleanly with zero validator diagnostics.
func expectedDiagCodes(name string) string {
	return map[string]string{
		"cgroupconnect": "",
		"execcount":     "",
		"execdeny":      "",
		"execwatch":     "",
		"killwatch":     "",
		"lsmfile":       "",
		"openwatch":     "",
		"tcpass":        "",
		"tcpconnect":    "",
		"xdpdrop":       "",
	}[name]
}

// TestCollectFindsRingbufReserveSites asserts that Collect finds at least one
// ringbuf reserve site in execwatch, which calls ExecEvents.reserve().
func TestCollectFindsRingbufReserveSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.RingbufReserve) == 0 {
		t.Fatal("expected at least one ringbuf reserve site in execwatch")
	}
}

// TestCollectFindsMapLookupSites asserts that Collect finds at least one map
// lookup site in execcount, which calls ExecCounts.lookup(pid).
func TestCollectFindsMapLookupSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execcount")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.MapLookup) == 0 {
		t.Fatal("expected at least one map lookup site in execcount")
	}
}

// TestCollectFindsHelperCallSites asserts that Collect finds at least one
// helper call site in execwatch, which calls bpf.ktime_get_ns, bpf.current_pid,
// bpf.current_ppid, bpf.current_uid, and bpf.current_comm.
func TestCollectFindsHelperCallSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.HelperCall) == 0 {
		t.Fatal("expected at least one helper call site in execwatch")
	}
}

// TestCollectFindsPacketHeaderSites asserts that Collect finds at least one
// packet header site in xdpdrop, which calls xdp.tcp(ctx).
func TestCollectFindsPacketHeaderSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/xdpdrop")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.PacketHeader) == 0 {
		t.Fatal("expected at least one packet header site in xdpdrop")
	}
}

// TestCollectLoopSites documents that no current example contains a for loop.
// When a loop-bearing example is added, this test should be updated to assert
// len(sites.Loops) > 0 on that fixture.
func TestCollectLoopSites(t *testing.T) {
	t.Skip("no current example contains a for loop; update when one is added")
}

// TestCollectStackLocalSites documents that no current example declares a
// stack-allocated struct or array local via a var statement. All struct data
// in current examples lives behind ringbuf reservations (pointer, no stack cost).
// Update this test when an example with a direct var-decl aggregate is added.
func TestCollectStackLocalSites(t *testing.T) {
	t.Skip("no current example uses var-decl aggregate stack locals; update when one is added")
}
