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

var examples = []string{
	"cgroupconnect", "eventbatch", "execwatch", "execcount", "execdeny",
	"killwatch", "lsmfile", "openwatch", "tcpconnect", "tcpass", "xdpdrop",
	"uprobeexec", "uretprobeexec",
	"fentryopen", "fexitopen",
	"rawtpenter",
	"sockopstrack",
	"structopstcp",
	"multifile-execcount",
	"imported-execcount",
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
	for _, name := range examples {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			cmd := exec.Command("go", "run", "./cmd/hzn", "workbench",
				"./examples/"+name, "-o", tmp)
			cmd.Dir = ".."
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("workbench: %v\n%s", err, stderr.String())
			}
			compareGoldenExamplesDir(t, name, tmp)
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
