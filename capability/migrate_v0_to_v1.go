package capability

import "errors"

// migrateV0ToV1 converts a raw v0 manifest JSON into a v1 Manifest.
// Stub: not yet implemented — Subtask 3b implements the full migration.
func migrateV0ToV1(raw []byte) (Manifest, error) {
	return Manifest{}, errors.New("v0 → v1 migration not yet implemented (pending Subtask 3b)")
}
