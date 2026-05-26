# Migrating Capability Manifests from v0 to v1

## TL;DR

Change the `schema` field from `"m31labs.dev/horizon/capability/v0"` to
`"m31labs.dev/horizon/capability/v1"`, reshape the `danger` field from a flat
string to an axes object, and call `capability.LoadManifest()` instead of
`json.Unmarshal` directly. For v0.2.x, `LoadManifest` accepts both schemas and
migrates v0 manifests in memory — so existing consumers get a zero-downtime
upgrade path.

## Why v1?

The v0 `danger` field carried a single flat word (`observe`, `mutate`, `drop`,
`block`, `privileged`) that collapsed three independent risk dimensions into one
scalar. This made it impossible for Continuum's policy engine to evaluate risk
independently across the effect boundary (what the program *does*), the blast
radius (what it *affects*), and the recovery path (how the effect *persists*).

v1 separates these into an orthogonal axes triple: `mode × scope × reversibility`.
The full design rationale lives in
`~/.hyphae/spaces/m31labs-horizon/decisions/0001-danger-taxonomy-v1.md`.

The Continuum integration spec (§A.2) defines the schema-version contract:
unknown schemas are rejected with error code `HZN3302`.

## Schema Version Field

v0 manifest header:

```json
{ "schema": "m31labs.dev/horizon/capability/v0", ... }
```

v1 manifest header:

```json
{ "schema": "m31labs.dev/horizon/capability/v1", ... }
```

Continuum rejects manifests with an unknown schema with a clear error. The Go
constant for each version:

```go
capability.SchemaV0 // "m31labs.dev/horizon/capability/v0" — migration only
capability.SchemaV1 // "m31labs.dev/horizon/capability/v1" — new manifests
```

## Danger Reshape

The flat `danger` string maps to a `DangerAxes` object with three required fields:

| v0 flat string | v1 mode   | v1 scope     | v1 reversibility |
|----------------|-----------|--------------|-----------------|
| `observe`      | observe   | event        | none            |
| `mutate`       | mutate    | process      | restart         |
| `drop`         | control   | network      | restart         |
| `block`        | control   | process      | restart         |
| `privileged`   | mutate    | system       | persistent      |

**v0 capability:**

```json
{
  "name": "kernel.process.exec.observe",
  "kind": "source",
  "danger": "observe",
  ...
}
```

**v1 capability:**

```json
{
  "name": "kernel.process.exec.observe",
  "kind": "source",
  "danger": {
    "mode": "observe",
    "scope": "event",
    "reversibility": "none"
  },
  ...
}
```

Valid axis values:

- `mode`: `observe` | `mutate` | `control`
- `scope`: `event` | `process` | `network` | `filesystem` | `system`
- `reversibility`: `none` | `restart` | `persistent`

## New Attach Surfaces

v1 manifests may reference seven new attach surfaces added in v0.2:

| Surface     | Minimum kernel | Description                                    |
|-------------|---------------|------------------------------------------------|
| `uprobe`    | 4.3           | User-space probe at a symbol in a binary       |
| `uretprobe` | 4.3           | User-space return probe                        |
| `fentry`    | 5.5           | Fast kernel function entry (BPF trampoline)    |
| `fexit`     | 5.5           | Fast kernel function exit (BPF trampoline)     |
| `raw_tp`    | 4.17          | Raw (unprocessed) kernel tracepoint            |
| `sockops`   | 4.13          | Socket operations cgroup hook                  |
| `struct_ops`| 5.6           | Custom kernel struct-ops implementation        |

Each surface ships with at least one example under `examples/` and registry
entries in `internal/registry/capability-namespaces-v1.json`.

## Map Access Annotations

> **Note:** `@steady_state_entries` and `@access_freq` are planned for v0.2
> (roadmap #22) and are not yet available. This section documents the expected
> shape when they ship.

These annotations on map declarations will surface in the v1 manifest for
capacity planning:

```
@max_entries(4096) @steady_state_entries(512) @access_freq("high")
map Counts: hash[u32, Count]
```

Corresponding manifest fields (both `omitempty`):

```json
{
  "name": "Counts",
  "kind": "hash",
  "max_entries": "4096",
  "steady_state_entries": "512",
  "access_freq": "high"
}
```

## Migration Path for Consumers

Use `capability.LoadManifest(raw []byte)` instead of `json.Unmarshal` directly.
The function signature is:

```go
func LoadManifest(raw []byte) (Manifest, []diag.Diagnostic, error)
```

- **v1 input**: parsed, validated, and returned with no diagnostics.
- **v0 input**: migrated to v1 in memory, returned with a `HZN3303`
  deprecation warning in the diagnostics slice. The returned `Manifest` is
  already v1 — consumers do not need to inspect the schema field.
- **Unknown schema**: returns an error containing "upgrade Horizon or downgrade
  Continuum".

Example:

```go
m, diags, err := capability.LoadManifest(raw)
if err != nil {
    return fmt.Errorf("load manifest: %w", err)
}
for _, d := range diags {
    log.Printf("manifest warning [%s]: %s", d.Code, d.Message)
}
// m.Schema == capability.SchemaV1 regardless of input schema version
```

Do not call `json.Unmarshal` directly into `capability.Manifest` for v0 inputs
— the `danger` field type is now `DangerAxes` (an object), not a string, so
unmarshalling v0 JSON will fail.

## Deprecation Timeline

| Release | v0 manifest behavior                               |
|---------|----------------------------------------------------|
| v0.2.x  | Loadable via `capability.LoadManifest`; emits `HZN3303` warning |
| v0.3.0  | v0 loader removed; `LoadManifest` rejects v0 with an error |

Horizon itself emits only v1 manifests as of v0.2. If you vendor pre-v0.2
manifests (e.g., from a build cache or a third-party artifact), call
`LoadManifest` before v0.3 ships to migrate them in memory and regenerate
the stored JSON as v1.
