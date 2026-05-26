#!/usr/bin/env bash
# scripts/kernel-matrix/run.sh
#
# Smoke-loads every .bpf.o under <bpf-obj-dir> against the BTF-enabled
# qcow2 kernel image identified by <kernel-version> in images.json.
#
# Usage: bash scripts/kernel-matrix/run.sh <kernel-version> <bpf-obj-dir>
# Exit 0 if all loads succeed; non-zero on any failure.
#
# TODO(#19 images): the boot/smoke implementation is stubbed until the
# canned qcow2 images publish at M31-Labs/horizon-kernel-images. The
# follow-up issue tracking image publication will fill in:
#   - sha256 verification of fetched qcow2 against images.json
#   - qemu invocation (KVM if available, TCG fallback)
#   - guest-side bpf loader (likely a tiny Go binary using cilium/ebpf
#     compiled static for the guest userspace)
#   - per-example pass/fail capture
#
# This skeleton exits non-zero with a clear message until that work lands,
# which is fine because the workflow trigger is `workflow_dispatch` only —
# it won't fire automatically on PRs.

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <kernel-version> <bpf-obj-dir>" >&2
    echo "  kernel-version: one of 5.10 / 5.15 / 6.1 / 6.6 (must appear in images.json)" >&2
    echo "  bpf-obj-dir:    directory containing .bpf.o files to load" >&2
    exit 2
fi

KERNEL="$1"
BPF_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_JSON="$SCRIPT_DIR/images.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "::error::jq is required (apt: jq)" >&2
    exit 2
fi

if [ ! -f "$IMAGES_JSON" ]; then
    echo "::error::images.json not found at $IMAGES_JSON" >&2
    exit 2
fi

if [ ! -d "$BPF_DIR" ]; then
    echo "::error::bpf-obj-dir does not exist: $BPF_DIR" >&2
    exit 2
fi

ENTRY=$(jq -r --arg k "$KERNEL" '.images[] | select(.kernel==$k)' "$IMAGES_JSON")
if [ -z "$ENTRY" ]; then
    echo "::error::kernel $KERNEL not in images.json" >&2
    exit 2
fi

URL=$(echo "$ENTRY" | jq -r '.url')
SHA=$(echo "$ENTRY" | jq -r '.sha256')
GATE=$(echo "$ENTRY" | jq -r '.gate')

echo "kernel: $KERNEL"
echo "image:  $URL"
echo "sha256: $SHA"
echo "gate:   $GATE"
echo "bpf:    $BPF_DIR ($(find "$BPF_DIR" -name '*.bpf.o' | wc -l) objects)"

# A valid sha256 is 64 lowercase hex characters. Anything else (the sentinel,
# a typo, an uppercase digest, a truncated value) is treated as "not yet
# published" so we never attempt to fetch unverified images.
if ! [[ "$SHA" =~ ^[a-f0-9]{64}$ ]]; then
    echo "::warning::kernel-matrix image for $KERNEL has invalid/missing sha256 ($SHA)"
    echo "::warning::see #19 follow-up issue: M31-Labs/horizon-kernel-images"
    echo "skipping boot/smoke until a valid sha256 is filled in"
    exit 78  # POSIX EX_CONFIG — distinguishes "stubbed" from "tested and failed"
fi

# TODO(#19 images): below here is where qemu-boot.sh gets invoked once
# images publish. Until then, the early-exit above guards against false
# greens or reds.
bash "$SCRIPT_DIR/qemu-boot.sh" "$URL" "$SHA" "$BPF_DIR"
