## Summary

Describe the user-visible or developer-visible change.

## Tests

List the local gates you ran, such as:

- `go test ./...`
- `make ci-go`
- `make ci-clang OUT=/tmp/horizon-ci`

## Hygiene

- [ ] This change does not commit private plans, scratch notes, logs, or local-only generated artifacts.
- [ ] Public examples, diagnostics, and generated fixtures are safe to share.
- [ ] Security-sensitive behavior is documented or covered by tests when relevant.
