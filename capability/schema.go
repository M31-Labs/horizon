package capability

// SchemaV0 is the original manifest schema identifier.
// Exported for migration only; new manifests always emit SchemaV1.
const SchemaV0 = "m31labs.dev/horizon/capability/v0"

// SchemaV1 is the v1 manifest schema identifier.
// New manifests always emit this schema. v0 manifests loaded via
// LoadManifest are migrated to v1 in memory.
const SchemaV1 = "m31labs.dev/horizon/capability/v1"
