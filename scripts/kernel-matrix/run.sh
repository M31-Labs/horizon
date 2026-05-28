#!/usr/bin/env bash
# scripts/kernel-matrix/run.sh
#
# Local reproduction of one kernel-matrix cell. Boots the LVH
# "complexity-test" image for <kernel-version> via the `lvh` CLI, runs the
# in-guest loader over <artifact-dir> (which must contain <stem>.bpf.o and
# the co-located <stem>.report.json from `make build-examples OUT=<dir>`),
# and compares the loads against each example's declared minimum kernel.
#
# CI does the same thing via the cilium/little-vm-helper action — this script
# is for local debugging. It needs the `lvh` CLI and QEMU; if they are
# absent it explains how to proceed rather than guessing.
#
# Usage: bash scripts/kernel-matrix/run.sh <kernel-version> <artifact-dir>
set -euo pipefail

KERNEL="${1:?usage: run.sh <kernel-version> <artifact-dir> (e.g. 6.1 dist)}"
ART_DIR="${2:?usage: run.sh <kernel-version> <artifact-dir>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_JSON="$SCRIPT_DIR/images.json"

command -v jq >/dev/null || { echo "::error::jq required" >&2; exit 2; }
[ -d "$ART_DIR" ] || { echo "::error::artifact dir not found: $ART_DIR" >&2; exit 2; }

REPO=$(jq -r '.image_repo' "$IMAGES_JSON")
IMAGE=$(jq -r '.image' "$IMAGES_JSON")
VERSION=$(jq -r --arg k "$KERNEL" '.images[] | select(.kernel==$k) | .version' "$IMAGES_JSON")
[ -n "$VERSION" ] && [ "$VERSION" != "null" ] || { echo "::error::kernel $KERNEL not in images.json" >&2; exit 2; }

echo "kernel:  $KERNEL"
echo "image:   $REPO/$IMAGE:$VERSION"
echo "objects: $(find "$ART_DIR" -name '*.bpf.o' | wc -l) in $ART_DIR"

if ! command -v lvh >/dev/null 2>&1; then
    cat >&2 <<EOF
::warning::the 'lvh' CLI is not installed — cannot boot a guest locally.
To run this cell locally:
  go install github.com/cilium/little-vm-helper/cmd/lvh@v0.0.30   # needs QEMU
Then re-run this script. In CI the cilium/little-vm-helper action does this
for you (see .github/workflows/kernel-matrix.yml). To exercise just the
comparison logic against a results file you already have:
  bash scripts/kernel-matrix/check-results.sh $KERNEL $ART_DIR <results.json>
EOF
    exit 78  # EX_CONFIG: tooling missing, not a test failure
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
lvh images pull --dir "$WORK" "$REPO/$IMAGE:$VERSION"
RESULTS="$ART_DIR/results.json"
lvh run \
    --image "$WORK/$IMAGE/$VERSION.qcow2" \
    --host-mount "$(pwd)" \
    --daemonize -p "2222:22"
# in-guest load + host-side compare
ssh -p 2222 root@localhost \
    "cd /host && ./scripts/kernel-matrix/in-guest-load.sh /host/$ART_DIR /host/$RESULTS"
bash "$SCRIPT_DIR/check-results.sh" "$KERNEL" "$ART_DIR" "$RESULTS"
