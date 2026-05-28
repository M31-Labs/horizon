#!/usr/bin/env bash
# scripts/kernel-matrix/capture-verifier-logs.sh
#
# Capture per-(kernel, example) verifier logs from `bpftool prog load -d`
# runs inside the qemu-booted kernel-matrix guests. The captured logs feed
# the real-kernel verifier-catalog corpus under
# `testdata/verifier-fixtures/real/<kernel>/<example>/{success,failure}/log.txt`,
# which the catalog tests use to regression-detect drift between Horizon's
# diagnostic catalog and what real kernels actually emit.
#
# Usage: bash scripts/kernel-matrix/capture-verifier-logs.sh <kernel-version> <bpf-obj-dir> <out-dir>
#   kernel-version: one of 5.10 / 5.15 / 6.1 / 6.6 (must appear in images.json)
#   bpf-obj-dir:    directory containing .bpf.o files to load (typically `make build-examples OUT=...`)
#   out-dir:        host-side root under which `<kernel>/<example>/<success|failure>/log.txt`
#                   directories will be written
#
# Exit codes:
#   0  — every per-example capture completed (success or failure load both
#        count as "captured"; only infrastructure failures fail the script)
#   2  — argument / config error
#   78 — EX_CONFIG: stubbed pending image publication (current state)
#   non-zero — infrastructure failure (image fetch, qemu launch, etc.)
#
# Intended workflow (when images publish):
#   1. Fetch + sha256-verify the qcow2 for <kernel-version> via images.json
#      (delegated to qemu-boot.sh's caching layer once that lands).
#   2. Boot the image under qemu with the host's <bpf-obj-dir> mounted into
#      the guest at /bpfobjs (9p virtfs, same shape as qemu-boot.sh's TODO
#      block).
#   3. In the guest, for each /bpfobjs/*.bpf.o:
#        - run `bpftool prog load -d <obj> /sys/fs/bpf/<basename>` capturing
#          stderr (the `-d` flag enables the verifier debug log)
#        - on success: write the log under success/log.txt
#        - on failure: write the log under failure/log.txt
#      The success-vs-failure split lets the host-side test
#      (TestVerifierCatalogRealFixtures) assert different invariants per
#      outcome. See `verifier/catalog_fixtures_test.go` for the discovery
#      walker that picks up this corpus.
#   4. Serialize the captured logs back to the host through a virtio-serial
#      console or the shared 9p mount; land them under
#      <out-dir>/<kernel>/<example>/<outcome>/log.txt.
#   5. After capture across all four kernels, the operator runs
#      `make verifier-fixtures-update` on the host to regenerate the
#      `expected.json` snapshots that pin diagnostic counts and per-line
#      enrichment shape.
#
# Dependencies (all gated behind image publication):
#   - bpftool in the guest's PATH (canned images we own should include it)
#   - jq + qemu-system-x86 on the host (same as run.sh)
#   - virtfs-9p support in the host kernel and qemu build (typical Linux)
#
# Handoff: see docs/internal/kernel-matrix-handoff.md for the full
# checklist of what changes when images publish (this script's real
# implementation, the kernel-matrix.yml trigger flip, the per-example
# capability-load smoke test, and the verifier-fixtures discovery walker
# extension for the `real/` subtree).
#
# TODO(#19 images): implementation stubbed until canned images publish
# at M31-Labs/horizon-kernel-images (issue #2).

set -euo pipefail

if [ $# -ne 3 ]; then
    echo "usage: $0 <kernel-version> <bpf-obj-dir> <out-dir>" >&2
    echo "  kernel-version: one of 5.10 / 5.15 / 6.1 / 6.6 (must appear in images.json)" >&2
    echo "  bpf-obj-dir:    directory containing .bpf.o files to load" >&2
    echo "  out-dir:        host-side root for captured logs" >&2
    exit 2
fi

echo "::error::capture-verifier-logs.sh stub — implementation pending image publication at M31-Labs/horizon-kernel-images (issue #2)" >&2
echo "::error::see docs/internal/kernel-matrix-handoff.md for the full pickup checklist" >&2
exit 78  # POSIX EX_CONFIG
