package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

func TestLoadLockfileEmpty(t *testing.T) {
	dir := t.TempDir()
	lf, diags, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if lf.Schema != "" {
		t.Fatalf("Schema = %q, want empty for missing file", lf.Schema)
	}
	if len(lf.Entries) != 0 {
		t.Fatalf("Entries = %d, want 0", len(lf.Entries))
	}
}

func TestLoadLockfileValid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hzn.lock", `{
		"schema": "m31labs.dev/horizon/lockfile/v1",
		"entries": [
			{
				"path": "github.com/m31labs/horizon-events",
				"version": "v1.2.3",
				"ref_resolved": "abc1234567890abcdef1234567890abcdef12345",
				"sha256": "deadbeef00000000000000000000000000000000000000000000000000000000"
			}
		]
	}`)
	lf, diags, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v, want none", diags)
	}
	if lf.Schema != LockfileSchema {
		t.Fatalf("Schema = %q, want %q", lf.Schema, LockfileSchema)
	}
	if len(lf.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(lf.Entries))
	}
	e := lf.Entries[0]
	if e.Path != "github.com/m31labs/horizon-events" {
		t.Fatalf("Entry.Path = %q", e.Path)
	}
	if e.Version != "v1.2.3" {
		t.Fatalf("Entry.Version = %q", e.Version)
	}
	if e.RefResolved != "abc1234567890abcdef1234567890abcdef12345" {
		t.Fatalf("Entry.RefResolved = %q", e.RefResolved)
	}
	if e.SHA256 != "deadbeef00000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("Entry.SHA256 = %q", e.SHA256)
	}
}

func TestLoadLockfileSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hzn.lock", `{
		"schema": "m31labs.dev/horizon/lockfile/v2-future",
		"entries": []
	}`)
	_, diags, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Code == "HZN1702" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1702 diagnostic, got %#v", diags)
	}
}

func TestLoadLockfileMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hzn.lock", `{not json`)
	_, diags, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile: %v", err)
	}
	if !diag.HasErrors(diags) {
		t.Fatalf("expected error diagnostic, got %#v", diags)
	}
}

func TestSaveLockfileSortedByPath(t *testing.T) {
	dir := t.TempDir()
	lf := Lockfile{
		Schema: LockfileSchema,
		Entries: []LockfileEntry{
			{Path: "github.com/zeta/zz", Version: "v1.0.0", RefResolved: strings.Repeat("z", 40), SHA256: strings.Repeat("z", 64)},
			{Path: "github.com/alpha/aa", Version: "v1.0.0", RefResolved: strings.Repeat("a", 40), SHA256: strings.Repeat("a", 64)},
			{Path: "github.com/mid/mm", Version: "v1.0.0", RefResolved: strings.Repeat("m", 40), SHA256: strings.Repeat("m", 64)},
		},
	}
	if err := SaveLockfile(dir, lf); err != nil {
		t.Fatalf("SaveLockfile: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hzn.lock"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var parsed Lockfile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(parsed.Entries) != 3 {
		t.Fatalf("Entries = %d, want 3", len(parsed.Entries))
	}
	want := []string{"github.com/alpha/aa", "github.com/mid/mm", "github.com/zeta/zz"}
	for i, w := range want {
		if parsed.Entries[i].Path != w {
			t.Fatalf("Entries[%d].Path = %q, want %q", i, parsed.Entries[i].Path, w)
		}
	}
}

func TestSaveLockfileAtomic(t *testing.T) {
	dir := t.TempDir()
	lf := Lockfile{
		Schema: LockfileSchema,
		Entries: []LockfileEntry{
			{Path: "github.com/foo/bar", Version: "v1.0.0", RefResolved: strings.Repeat("a", 40), SHA256: strings.Repeat("a", 64)},
		},
	}
	if err := SaveLockfile(dir, lf); err != nil {
		t.Fatalf("SaveLockfile: %v", err)
	}
	// Post-condition: no .tmp file left behind, and hzn.lock exists.
	if _, err := os.Stat(filepath.Join(dir, "hzn.lock")); err != nil {
		t.Fatalf("hzn.lock missing: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("stale tmp file %q after SaveLockfile", e.Name())
		}
	}
}

func TestSaveLockfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := Lockfile{
		Schema: LockfileSchema,
		Entries: []LockfileEntry{
			{Path: "github.com/foo/bar", Version: "v1.2.3", RefResolved: strings.Repeat("a", 40), SHA256: strings.Repeat("b", 64)},
		},
	}
	if err := SaveLockfile(dir, original); err != nil {
		t.Fatalf("SaveLockfile: %v", err)
	}
	loaded, diags, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile: %v", err)
	}
	if diag.HasErrors(diags) {
		t.Fatalf("diagnostics = %#v", diags)
	}
	if loaded.Schema != original.Schema {
		t.Fatalf("Schema round-trip = %q, want %q", loaded.Schema, original.Schema)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].Path != "github.com/foo/bar" {
		t.Fatalf("Entries round-trip = %#v", loaded.Entries)
	}
}
