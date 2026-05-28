package compiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"m31labs.dev/horizon/compiler/diag"
)

// LockfileSchema is the canonical schema identifier for the v1 hzn.lock
// format. Files carrying a different schema string are rejected with
// diagnostic HZN1702. The string mirrors cedar's clang-catalog and
// helpers-v1 conventions so schema identifiers across Horizon
// artifacts have a consistent shape.
//
// Path: lockfile is "m31labs.dev/horizon/lockfile/v1"; bump to /v2
// only on a breaking JSON shape change.
const LockfileSchema = "m31labs.dev/horizon/lockfile/v1"

// LockfileName is the on-disk filename for the lockfile. Lives at the
// build root (the directory passed to `hzn check`).
const LockfileName = "hzn.lock"

// LockfileEntry pins one imported package to a specific git ref and
// content sha256. Path is the user-facing import path (without the
// `@<version>` suffix). Version is the user-supplied pin (semver tag
// like "v1.2.3" or a hex SHA prefix). RefResolved is the full 40-char
// git SHA resolved at lockfile write time — the canonical pin. SHA256
// is the content hash computed over the resolved package directory
// tree; verified on every load.
type LockfileEntry struct {
	Path        string `json:"path"`
	Version     string `json:"version"`
	RefResolved string `json:"ref_resolved"`
	SHA256      string `json:"sha256"`
}

// Lockfile is the in-memory shape of `hzn.lock`. Schema must equal
// LockfileSchema on every load; Entries is sorted by Path on save for
// diff stability.
type Lockfile struct {
	Schema  string          `json:"schema"`
	Entries []LockfileEntry `json:"entries"`
}

// LookupEntry returns the entry for path, if any. Match is exact on
// the user-facing import path (the `@version` suffix is stripped by
// the resolver before the lookup).
func (lf Lockfile) LookupEntry(path string) (LockfileEntry, bool) {
	for _, e := range lf.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return LockfileEntry{}, false
}

// LoadLockfile reads `hzn.lock` from dir. A missing file is not an
// error — an empty Lockfile is returned with no diagnostics. Schema
// mismatch surfaces as HZN1702; malformed JSON or I/O errors surface
// as generic error diagnostics. Hard I/O failures (e.g. permission
// denied on the file when it does exist) return a non-nil error.
func LoadLockfile(dir string) (Lockfile, []diag.Diagnostic, error) {
	path := filepath.Join(dir, LockfileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Lockfile{}, nil, nil
		}
		return Lockfile{}, nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lf Lockfile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return Lockfile{}, []diag.Diagnostic{{
			Code:     "HZN1702",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("lockfile %s is not valid JSON: %v", path, err),
			Suggest:  "regenerate the lockfile via `hzn get` or delete it to start fresh",
		}}, nil
	}
	if lf.Schema != LockfileSchema {
		return lf, []diag.Diagnostic{{
			Code:     "HZN1702",
			Severity: diag.SeverityError,
			Message:  fmt.Sprintf("lockfile %s has unknown schema %q (expected %q)", path, lf.Schema, LockfileSchema),
			Suggest:  "this Horizon toolchain only understands lockfile schema " + LockfileSchema + "; upgrade the toolchain or regenerate the lockfile",
		}}, nil
	}
	return lf, nil, nil
}

// SaveLockfile writes lf to `<dir>/hzn.lock` atomically — write to a
// sibling `.hzn.lock.tmp`, then rename. Entries are sorted by Path on
// write so two equivalent lockfiles produce byte-identical files. The
// schema field is force-set to LockfileSchema even if the caller
// passed an empty (or stale) value, so a caller cannot accidentally
// produce a file the loader will reject.
func SaveLockfile(dir string, lf Lockfile) error {
	lf.Schema = LockfileSchema
	sort.SliceStable(lf.Entries, func(i, j int) bool {
		return lf.Entries[i].Path < lf.Entries[j].Path
	})
	raw, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lockfile: %w", err)
	}
	// Trailing newline — every other Horizon JSON artifact has one;
	// editors and `cat` are nicer.
	raw = append(raw, '\n')
	tmp := filepath.Join(dir, "."+LockfileName+".tmp")
	final := filepath.Join(dir, LockfileName)
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write tmp lockfile %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		// Best-effort cleanup so a failed rename does not litter
		// the build dir with a stale .tmp.
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, final, err)
	}
	return nil
}
