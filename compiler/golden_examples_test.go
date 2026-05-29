package compiler_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "regenerate testdata/golden/examples baselines")

// exampleFixture describes one example registered with the golden
// harness. Name is the directory under ./examples and is the only
// required field. Env supplies optional per-example process
// environment overrides — used by the multifile-buildtag fixture to
// pin a deterministic BuildContext via HORIZON_BUILD_* env vars so
// the golden output matches regardless of CI host OS/arch/kernel.
type exampleFixture struct {
	Name string
	Env  []string
	// EnvBuilder allows the fixture to compute env vars at test
	// time — needed by remoteimport-execcount, which sets
	// HORIZON_CACHE_ROOT to the absolute path of the in-repo
	// remote-fixture tree. Static Env entries (from the Env field)
	// are appended after the builder's output.
	EnvBuilder func(t *testing.T) []string
}

var examples = []exampleFixture{
	{Name: "cgroupconnect"}, {Name: "eventbatch"}, {Name: "execwatch"},
	{Name: "execcount"}, {Name: "execdeny"},
	{Name: "killwatch"}, {Name: "lsmfile"}, {Name: "openwatch"},
	{Name: "tcpconnect"}, {Name: "tcpass"}, {Name: "xdpdrop"},
	{Name: "uprobeexec"}, {Name: "uretprobeexec"},
	{Name: "fentryopen"}, {Name: "fexitopen"},
	{Name: "rawtpenter"},
	{Name: "sockopstrack"},
	{Name: "structopstcp"},
	{Name: "multifile-execcount"},
	{Name: "imported-execcount"},
	{Name: "imported-reexport"},
	{Name: "helperctor-execwatch"},
	{Name: "interproc-execwatch"},
	{
		Name: "multifile-buildtag",
		Env: []string{
			"HORIZON_BUILD_OS=linux",
			"HORIZON_BUILD_ARCH=amd64",
			"HORIZON_BUILD_KERNEL=5.15",
			"HORIZON_BUILD_BTF=1",
		},
	},
	{
		Name: "remoteimport-execcount",
		// Points the resolver's content-addressed cache at the
		// pre-populated in-repo fixture tree so the workbench
		// invocation never touches the network. The fixture is
		// laid out as cacheRoot/<sha256(repo)[:32]>/<ref>/...
		// matching what compiler.cacheKey produces for the
		// example's hzn.lock entry. Real-network round-trip is
		// gated behind HORIZON_NETWORK_TESTS — see
		// docs/internal/remote-imports-testing.md.
		EnvBuilder: func(t *testing.T) []string {
			abs, err := filepath.Abs(filepath.Join("..", "testdata", "remote-fixtures"))
			if err != nil {
				t.Fatalf("abs remote-fixtures: %v", err)
			}
			return []string{
				"HORIZON_CACHE_ROOT=" + abs,
				"HORIZON_NETWORK_TESTS=",
			}
		},
	},
}

// Fields stripped before comparison because they vary per-run.
var volatileReportFields = []string{
	"generated_at",
	"tool",
	"artifacts",
	"artifact_details",
	"paths",
}

func TestGoldenExamplesWorkbench(t *testing.T) {
	for _, ex := range examples {
		t.Run(ex.Name, func(t *testing.T) {
			tmp := t.TempDir()
			cmd := exec.Command("go", "run", "./cmd/hzn", "workbench",
				"./examples/"+ex.Name, "-o", tmp)
			cmd.Dir = ".."
			var extraEnv []string
			if ex.EnvBuilder != nil {
				extraEnv = append(extraEnv, ex.EnvBuilder(t)...)
			}
			extraEnv = append(extraEnv, ex.Env...)
			if len(extraEnv) > 0 {
				cmd.Env = append(os.Environ(), extraEnv...)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("workbench: %v\n%s", err, stderr.String())
			}
			compareGoldenExamplesDir(t, ex.Name, tmp)
		})
	}
}

func compareGoldenExamplesDir(t *testing.T, name, generated string) {
	golden := filepath.Join("..", "testdata", "golden", "examples", name)
	files, err := filepath.Glob(filepath.Join(generated, "*"))
	if err != nil {
		t.Fatalf("glob generated: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		got, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read generated %s: %v", base, err)
		}
		if filepath.Ext(base) == ".json" {
			got = stripVolatile(t, got)
		}
		goldenPath := filepath.Join(golden, base)
		if *updateGolden {
			if err := os.MkdirAll(golden, 0o755); err != nil {
				t.Fatalf("mkdir golden: %v", err)
			}
			if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			continue
		}
		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden %s: %v (run `make golden-update`?)", base, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from golden — run `make golden-update` if intended", base)
		}
	}
}

func stripVolatile(t *testing.T, raw []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw // not an object; nothing to strip
	}
	for _, f := range volatileReportFields {
		delete(doc, f)
	}
	// Strip generated.path from source maps
	if gen, ok := doc["generated"].(map[string]any); ok {
		delete(gen, "path")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}
