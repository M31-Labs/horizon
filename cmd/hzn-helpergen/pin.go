// Package main — pin metadata for the libbpf source the helper-registry
// candidate generator consumes.
//
// The pin is updated by hand when refreshing Horizon's helper annotations
// against a newer libbpf release. Bumping these consts is a reviewable
// diff; the workflow is documented in
// docs/internal/helper-registry-regeneration.md.
//
// O-9 resolution (Phase 1 cedar Task 4): the plan originally proposed a
// second sha256 for src/bpf_helpers.h (named LibbpfHelpersTxtSHA256). On
// inspection that file is a user-facing macro/type-import header that
// only #includes bpf_helper_defs.h — the parser doesn't consume it.
// Dropped from the pin to keep nightly verification minimal.
//
// O-2 resolution: modern libbpf releases ship the helper-defs header at
// src/bpf_helper_defs.h. The plan's original path (tools/lib/bpf/...) is
// the old in-kernel mirror location and returns 404 against post-v0.6
// libbpf release tags.
package main

const (
	// LibbpfRepoURL is the canonical libbpf source repository.
	LibbpfRepoURL = "https://github.com/libbpf/libbpf"

	// LibbpfCommit is the exact commit Horizon's helper annotations are
	// reconciled against. Always a release-tag commit, never a main-branch
	// tip. Pinned at libbpf v1.7.0.
	LibbpfCommit = "f5dcbae736e5d7f83a35718e01be1a8e3010fa39"

	// LibbpfHelperDefsSHA256 is the sha256 of the
	// src/bpf_helper_defs.h file at LibbpfCommit. The tool refuses to
	// proceed if the fetched file's hash does not match.
	LibbpfHelperDefsSHA256 = "ebcd44514b37cbd4459b5b637dcb39a43d9adee94496c3afe2ee5219b5c8a3a5"

	// LibbpfHelperDefsPath is the in-repo path the tool fetches.
	LibbpfHelperDefsPath = "src/bpf_helper_defs.h"
)

// LibbpfHelperDefsURL returns the raw.githubusercontent.com URL for the
// pinned header file.
func LibbpfHelperDefsURL() string {
	return "https://raw.githubusercontent.com/libbpf/libbpf/" + LibbpfCommit + "/" + LibbpfHelperDefsPath
}
