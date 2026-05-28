# Remote-imports testing pattern

> Internal doc — contributors only. Public migration guidance lives in
> `docs/migrations/v0.2-to-v0.3.md`.

`hzn check` and friends resolve `github.com/<org>/<repo>@<version>`
imports by fetching the repo into a content-addressed cache and
verifying the cached content's sha256 against `hzn.lock`. The default
test suite must never touch the network — CI sandboxes are often
offline, and intermittent flake on `git ls-remote` would erode trust
in the green light.

This doc explains the two test seams that keep `make ci-go` hermetic
and the opt-in flag for real-network verification.

## Mock-fetcher pattern (Go unit tests)

`compiler/fetcher.go` exposes two package-level function variables
that production wires to `exec.Command("git", ...)`:

- `gitClone(repo, ref, dest string) error` — invoked on cache miss.
- `resolveRef(repoURL, version string) (string, error)` — invoked in
  lockfile-update mode to map a tag/branch to a full SHA.

Tests overwrite either variable to return deterministic results
without invoking git. The pattern:

```go
prev := gitClone
gitClone = func(repo, ref, dest string) error {
    // populate dest with fixture contents
    return os.WriteFile(filepath.Join(dest, "events.hzn"), ..., 0o644)
}
defer func() { gitClone = prev }()
```

For tests that exercise the cache-hit path, skip the stub entirely
and pre-populate the cache directory directly. The fetcher's `Fetch`
short-circuits when the destination already exists.

## Pre-populated fixture pattern (golden examples)

The `remoteimport-execcount` golden example demonstrates the
end-to-end flow without a network. The setup:

1. `examples/remoteimport-execcount/prog.hzn` declares the import
   `github.com/m31labs/horizon-test-events@v1.0.0`.
2. `examples/remoteimport-execcount/hzn.lock` pins the version + the
   content sha256 of the fixture (not a real upstream repo's hash —
   the fixture is the source of truth).
3. `testdata/remote-fixtures/<sha256(repo)[:32]>/<ref>/events.hzn`
   holds the fixture content.
4. The golden harness sets `HORIZON_CACHE_ROOT` to the absolute path
   of `testdata/remote-fixtures` so the resolver finds the fixture
   immediately (cache hit) and skips the fetch entirely.

The cache key (`sha256(repo)[:32]`) is computed from the canonical
import path. To compute it for a new fixture, use:

```sh
echo -n "github.com/m31labs/horizon-test-events" | sha256sum | cut -c1-32
```

The fixture's content sha256 (what gets pinned in `hzn.lock`) is the
result of `compiler.hashDirSHA256(<fixture-dir>)` — the same routine
the resolver runs at verify time. Regenerate it after editing the
fixture or the test will fail with `HZN1700` (checksum mismatch).

## Real-network verification (opt-in)

Round-trip tests that actually clone from github.com are gated behind
the `HORIZON_NETWORK_TESTS` env var. Default is unset — `make ci-go`
runs hermetic. To run network tests locally:

```sh
HORIZON_NETWORK_TESTS=1 go test ./compiler/...
```

These tests live outside the default ci-go path on purpose: they're
slow, they need git auth, and they exercise upstream rate limits.
Use them when:

- Validating a new clone-url shape (e.g. m31labs.dev meta-redirect).
- Diagnosing a production fetch regression.
- Releasing a new toolchain version against current upstream.

## Adding a new remote-import example

1. Pick a fictional repo path (e.g. `github.com/m31labs/horizon-test-foo`).
2. Compute its cache key: `echo -n "<path>" | sha256sum | cut -c1-32`.
3. Create `testdata/remote-fixtures/<key>/<ref>/<one or more>.hzn`.
4. Compute the fixture's content sha256 via a one-off Go program
   that calls `compiler.hashDirSHA256(<fixture-dir>)`.
5. Write `examples/<name>/prog.hzn` that imports the fictional repo.
6. Write `examples/<name>/hzn.lock` pinning the version + sha256.
7. Register the example in `compiler/golden_examples_test.go` with
   an `EnvBuilder` that sets `HORIZON_CACHE_ROOT` to the abs path of
   `testdata/remote-fixtures`.
8. `make golden-update` to materialize the goldens.

## Why not vendor the fixture in `examples/<name>/vendor/`?

Vendoring is the v0.2 path and it still works — it's the offline
fallback documented in the migration guide. But the point of these
golden examples is to exercise the **remote-import resolution path**
(lockfile lookup, sha256 verification, cache hit). Vendoring
short-circuits all of that before the new code runs. The
`testdata/remote-fixtures/` layout makes the cache externally
addressable from the test harness without polluting the example
directory with an internal artifact.
