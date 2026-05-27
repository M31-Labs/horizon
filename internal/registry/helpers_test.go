package registry

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// expectedHelperNames is the canonical compiler-known helper surface as
// of v0.3. Any drift between this set and the embedded registry is a
// build breaker. The cross-package drift test in
// capability/helper_effects_drift_test.go re-derives the same set from
// the compiler-side helper inventory (compilerHelperRequirements +
// mapMethodHelper + the v0.3 context-accessor / packet-parser /
// endianness intrinsic surface) to keep the two sides of the registry
// contract pinned to one another.
var expectedHelperNames = []string{
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

func TestHelpersJSONParses(t *testing.T) {
	r := MustLoadHelpers()
	if r.Schema != "m31labs.dev/horizon/helpers/v1" {
		t.Fatalf("schema = %q, want m31labs.dev/horizon/helpers/v1", r.Schema)
	}
	if r.Version != "1" {
		t.Fatalf("version = %q, want 1", r.Version)
	}
	if len(r.Helpers) == 0 {
		t.Fatalf("no helpers loaded")
	}
}

func TestHelpersJSONCoversKnownInventory(t *testing.T) {
	r := MustLoadHelpers()
	got := make([]string, 0, len(r.Helpers))
	for _, h := range r.Helpers {
		got = append(got, h.Name)
	}
	sort.Strings(got)

	want := append([]string(nil), expectedHelperNames...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("helper count = %d, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("helper[%d] = %q, want %q\n got: %v\nwant: %v", i, got[i], want[i], got, want)
		}
	}
}

var (
	allowedResourceVerbs = map[string]bool{
		"":        true, // omitted is allowed
		"reserve": true,
		"submit":  true,
		"discard": true,
		"lookup":  true,
		"update":  true,
		"delete":  true,
		"none":    true,
	}
	allowedTopLevelTokens = map[string]bool{
		"task.tgid":                      true,
		"task.pid":                       true,
		"task.uid":                       true,
		"task.gid":                       true,
		"task.comm":                      true,
		"task.real_parent.tgid":          true,
		"kernel.time.monotonic":          true,
		"userspace.string":               true,
		"userspace.bytes":                true,
		"kernel.syscall.arg1":            true,
		"kernel.syscall.arg2":            true,
		"kernel.syscall.arg3":            true,
		"kernel.syscall.arg4":            true,
		"kernel.syscall.arg5":            true,
		"kernel.syscall.return":          true,
		"kernel.socket.family":           true,
		"kernel.socket.type":             true,
		"kernel.socket.protocol":         true,
		"kernel.socket.dst_port":         true,
		"kernel.socket.dst_ip4":          true,
		"kernel.socket.src_ip4":          true,
		"kernel.network.packet.ethernet": true,
		"kernel.network.packet.ipv4":     true,
		"kernel.network.packet.tcp":      true,
		"kernel.network.packet.udp":      true,
	}
	allowedRequiresTokens = map[string]bool{
		"task_struct.real_parent": true,
	}
	resourceTokenPattern = regexp.MustCompile(`^(map|ringbuf):(\$|[A-Za-z_][A-Za-z0-9_]*)$`)
)

func TestHelpersJSONShapesAreWellFormed(t *testing.T) {
	r := MustLoadHelpers()
	for _, h := range r.Helpers {
		if h.Name == "" {
			t.Fatalf("entry has empty name: %+v", h)
		}
		if h.KernelSymbol == "" {
			t.Fatalf("entry %q has empty kernel_symbol", h.Name)
		}
		if !allowedResourceVerbs[h.Resource] {
			t.Fatalf("entry %q has illegal resource verb %q", h.Name, h.Resource)
		}
		for _, tok := range h.Observes {
			if !allowedTopLevelTokens[tok] && !resourceTokenPattern.MatchString(tok) {
				t.Fatalf("entry %q observes illegal token %q", h.Name, tok)
			}
		}
		for _, tok := range h.Mutates {
			if !allowedTopLevelTokens[tok] && !resourceTokenPattern.MatchString(tok) {
				t.Fatalf("entry %q mutates illegal token %q", h.Name, tok)
			}
		}
		for _, tok := range h.Requires {
			if !allowedRequiresTokens[tok] {
				t.Fatalf("entry %q requires illegal token %q (BTF-only vocabulary in v0.2)", h.Name, tok)
			}
		}
	}
}

// TestHelpersJSONMatchesHyphaeSource asserts that the embedded JSON is
// byte-identical to the canonical Hyphae spec. Skips defensively if the
// canonical file is unreachable (e.g. CI runners that don't sync the
// hyphae workspace), mirroring the defensive-skip pattern documented in
// the plan for cedar's namespace drift test.
func TestHelpersJSONMatchesHyphaeSource(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("user home unavailable: %v", err)
	}
	canonical := filepath.Join(home, ".hyphae", "spaces", "m31labs-horizon", "specs", "helpers-v1.json")
	hyphae, err := os.ReadFile(canonical)
	if err != nil {
		t.Skipf("hyphae canonical not present at %s: %v", canonical, err)
	}
	if !bytes.Equal(hyphae, helpersJSON) {
		t.Fatalf("embedded helpers-v1.json drifts from hyphae canonical at %s\nre-vendor the file (byte-identical)", canonical)
	}
}
