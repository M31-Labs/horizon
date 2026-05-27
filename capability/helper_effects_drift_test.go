package capability

import (
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/internal/registry"
)

// compilerKnownHelperSurface enumerates every helper surface name the
// Horizon compiler currently recognizes. Multiple sources drive this set:
//
//   - compilerHelperRequirements(name string) — six bpf.* intrinsics
//     (current_pid, current_ppid, current_uid, current_comm,
//     probe_read_user_str, ktime_get_ns) that emit kernel BPF helper
//     calls. Endianness intrinsics (bpf.{htons,htonl,ntohs,ntohl}) and
//     context accessors are deliberately NOT in that switch because
//     they expand to inline byte-swaps or PT_REGS_PARMn macros with no
//     kernel-symbol requirement.
//   - mapMethodHelper(method string) — six map / ringbuf methods
//     (lookup, update, delete, reserve, submit, discard). Map methods
//     materialize as surface names map.lookup / map.update / map.delete;
//     ringbuf methods as ringbuf.reserve / ringbuf.submit / ringbuf.discard.
//     The test asserts both directions of the mapping (the method label
//     resolves via mapMethodHelper, and the qualified surface name lives
//     in the registry).
//   - Context-accessor and packet-parser intrinsics — v0.3 adds
//     kprobe.arg1..arg5, kretprobe.ret, cgroup.{family,sock_type,
//     protocol,dst_port,dst_ip4,src_ip4,ip4}, and xdp.{eth,ipv4,tcp,
//     udp,ntohs}. These expand inline at the call site; the registry
//     entry exists for governance-layer observation, not for
//     kernel-symbol resolution.
//   - Endianness intrinsics — v0.3 adds bpf.{htons,htonl,ntohs,ntohl}
//     with explicit empty observe / mutate sets (pure compute).
//
// Adding a helper to either compiler switch — or to the v0.3 context /
// parser intrinsic surface — without updating this set is a
// build-breaking regression — that's the whole point of this test.
var compilerKnownHelperSurface = []string{
	"bpf.current_comm",
	"bpf.current_pid",
	"bpf.current_ppid",
	"bpf.current_uid",
	"bpf.htonl",
	"bpf.htons",
	"bpf.ktime_get_ns",
	"bpf.ntohl",
	"bpf.ntohs",
	"bpf.probe_read_user_str",
	"cgroup.dst_ip4",
	"cgroup.dst_port",
	"cgroup.family",
	"cgroup.ip4",
	"cgroup.protocol",
	"cgroup.sock_type",
	"cgroup.src_ip4",
	"kprobe.arg1",
	"kprobe.arg2",
	"kprobe.arg3",
	"kprobe.arg4",
	"kprobe.arg5",
	"kretprobe.ret",
	"map.delete",
	"map.lookup",
	"map.update",
	"ringbuf.discard",
	"ringbuf.reserve",
	"ringbuf.submit",
	"xdp.eth",
	"xdp.ipv4",
	"xdp.ntohs",
	"xdp.tcp",
	"xdp.udp",
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

// TestCompilerHelperRequirementsResolvesEveryKnownBPFName asserts the
// compilerHelperRequirements kernel-symbol resolver covers every helper
// surface name that emits a BPF helper kernel call. The assertion only
// fires for the BPF helper-call subset of compilerKnownHelperSurface;
// the helper families below intentionally fail
// compilerHelperRequirements (they have no kernel-symbol requirement at
// the helper-call level) and are SKIPPED:
//
//   - bpf.htons / bpf.htonl / bpf.ntohs / bpf.ntohl — endianness ops
//     compile to inline byte-swaps; no kernel symbol involved.
//   - kprobe.arg1..arg5, kretprobe.ret — expand to PT_REGS_PARMn /
//     PT_REGS_RC macros at the call site; no kernel symbol involved.
//   - cgroup.{family,sock_type,protocol,dst_port,dst_ip4,src_ip4,ip4} —
//     either bpf_sock_addr field accessors (compile to direct context
//     loads, no helper call) or pure construction (ip4).
//   - xdp.{eth,ipv4,tcp,udp,ntohs} — packet-parser intrinsics
//     compiled inline; no kernel helper call.
//   - map.* / ringbuf.* — kernel-symbol resolution lives in the
//     mapMethodHelper switch, not compilerHelperRequirements. The
//     parallel assertion is TestMapMethodHelperResolvesEveryKnownMapAndRingbufMethod
//     below.
//
// The drift test still requires registry entries for every helper in
// compilerKnownHelperSurface (asserted by
// TestRegistryCoversAllCompilerKnownHelpers); only the kernel-symbol
// resolution path is orthogonal for the skipped families. The
// annotation captures the *semantic effect*, while
// compilerHelperRequirements tracks *kernel-symbol requirements* — the
// two are intentionally decoupled.
func TestCompilerHelperRequirementsResolvesEveryKnownBPFName(t *testing.T) {
	for _, name := range compilerKnownHelperSurface {
		if !requiresKernelHelperSymbol(name) {
			continue
		}
		syms := compilerHelperRequirements(name)
		if len(syms) == 0 {
			t.Errorf("compilerHelperRequirements(%q) returned no symbols — switch case missing or surface name drifted", name)
		}
	}
}

// requiresKernelHelperSymbol reports whether a helper surface name
// emits a kernel BPF helper call (and thus has an entry in
// compilerHelperRequirements). Returns false for context accessors,
// packet parsers, endianness intrinsics, and map / ringbuf resource
// verbs — see the doc comment on
// TestCompilerHelperRequirementsResolvesEveryKnownBPFName for the
// rationale on each skipped family.
func requiresKernelHelperSymbol(name string) bool {
	if isEndiannessIntrinsic(name) {
		return false
	}
	if strings.HasPrefix(name, "kprobe.") || strings.HasPrefix(name, "kretprobe.") {
		return false
	}
	if strings.HasPrefix(name, "cgroup.") {
		return false
	}
	if strings.HasPrefix(name, "xdp.") {
		return false
	}
	if strings.HasPrefix(name, "map.") || strings.HasPrefix(name, "ringbuf.") {
		// map / ringbuf resource verbs resolve via mapMethodHelper, not
		// compilerHelperRequirements. The parallel drift test
		// TestMapMethodHelperResolvesEveryKnownMapAndRingbufMethod covers
		// them.
		return false
	}
	return strings.HasPrefix(name, "bpf.")
}

// isEndiannessIntrinsic returns true for the four bpf.* endianness
// helpers (htons, htonl, ntohs, ntohl) that compile to inline byte-swaps
// with no kernel-symbol requirement. Used by drift tests to skip the
// kernel-symbol resolution assertion for these helpers.
func isEndiannessIntrinsic(name string) bool {
	switch name {
	case "bpf.htons", "bpf.htonl", "bpf.ntohs", "bpf.ntohl":
		return true
	default:
		return false
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
