package validate_test

import (
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
)

func TestLSMDenyRequiresDominatingCellScopeGuard(t *testing.T) {
	tests := []struct {
		name, body string
		want1497   bool
	}{
		{"guarded", `id := bpf.current_cgroup_id()
scope := CellScope.lookup(id)
if scope == nil { return lsm.Allow }
return lsm.Deny`, false},
		{"unguarded", `id := bpf.current_cgroup_id()
scope := CellScope.lookup(id)
return lsm.Deny`, true},
		{"bypass", `id := bpf.current_cgroup_id()
scope := CellScope.lookup(id)
if id == 1 { return lsm.Deny }
if scope == nil { return lsm.Allow }
return lsm.Deny`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := `package probes
type CellScopeVal struct { fs_dev u32 }
@max_entries(4096)
map CellScope hash[u64, CellScopeVal]
@lsm("file_open")
func Gate(ctx lsm.Context) i32 {
` + test.body + "\n}\n"
			if err := os.WriteFile(filepath.Join(dir, "gate.hzn"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := compiler.AnalyzePath(dir)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, diagnostic := range result.Diagnostics {
				found = found || diagnostic.Code == "HZN1497"
			}
			if found != test.want1497 {
				t.Fatalf("HZN1497=%v want %v; diagnostics=%#v", found, test.want1497, result.Diagnostics)
			}
			if !test.want1497 && diag.HasErrors(result.Diagnostics) {
				t.Fatalf("guarded program diagnostics=%#v", result.Diagnostics)
			}
		})
	}
}
