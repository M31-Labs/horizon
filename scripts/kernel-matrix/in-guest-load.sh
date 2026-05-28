#!/usr/bin/env bash
# scripts/kernel-matrix/in-guest-load.sh
#
# Runs INSIDE an LVH guest VM (booted by the cilium/little-vm-helper action
# or the `lvh` CLI). Attempts a real verifier load of every <stem>.bpf.o in
# the object directory and records, per object, whether the kernel verifier
# accepted it. The verifier log for a rejected load is written verbatim to a
# sibling logs/ directory — NOT embedded in JSON — so we never depend on
# escaping arbitrary verifier text (which carries newlines, quotes, and
# register dumps) through a shell. results.json therefore only ever contains
# object names and booleans, which is trivially valid JSON.
#
# A rejected load is a data point, not an error: this script only hard-fails
# on setup problems (missing bpftool / object dir). The host-side comparator
# (check-results.sh) decides pass/fail.
#
# Usage (inside guest): in-guest-load.sh <obj-dir> <results-json-out>
#   logs are written to "$(dirname <results-json-out>)/logs/<object>.log"
set -uo pipefail

OBJ_DIR="${1:?usage: in-guest-load.sh <obj-dir> <results-json-out>}"
OUT="${2:?usage: in-guest-load.sh <obj-dir> <results-json-out>}"

if ! command -v bpftool >/dev/null 2>&1; then
    echo "FATAL: bpftool not found in guest" >&2
    exit 2
fi
if [ ! -d "$OBJ_DIR" ]; then
    echo "FATAL: object dir not found: $OBJ_DIR" >&2
    exit 2
fi

KREL="$(uname -r)"
PIN_BASE=/sys/fs/bpf/kmatrix
LOG_DIR="$(dirname "$OUT")/logs"
mkdir -p "$LOG_DIR"
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# results.json: {kernel_release, results:[{object, loaded}]} — booleans and
# object stems only, so no escaping is ever required.
{
    printf '{\n  "kernel_release": "%s",\n  "results": [\n' "$KREL"
    first=1
    shopt -s nullglob
    for obj in "$OBJ_DIR"/*.bpf.o; do
        stem="$(basename "$obj" .bpf.o)"
        rm -rf "$PIN_BASE" 2>/dev/null || true
        # loadall exercises the verifier on every program in the object.
        log="$(bpftool prog loadall "$obj" "$PIN_BASE" 2>&1)"; rc=$?
        rm -rf "$PIN_BASE" 2>/dev/null || true
        if [ "$rc" -eq 0 ]; then loaded=true; else loaded=false; printf '%s\n' "$log" > "$LOG_DIR/$stem.log"; fi

        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"object": "%s", "loaded": %s}' "$stem" "$loaded"
        echo "load $stem: rc=$rc loaded=$loaded" >&2
    done
    printf '\n  ]\n}\n'
} > "$OUT"

echo "--- results written to $OUT ---" >&2
cat "$OUT" >&2
