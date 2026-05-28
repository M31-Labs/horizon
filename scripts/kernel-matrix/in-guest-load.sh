#!/usr/bin/env bash
# scripts/kernel-matrix/in-guest-load.sh
#
# Runs INSIDE an LVH guest VM (booted by the cilium/little-vm-helper action
# or the `lvh` CLI). Attempts a real verifier load of every <stem>.bpf.o in
# the object directory and records, per object, whether the kernel verifier
# accepted it plus the verifier log on rejection.
#
# It never fails the VM step on a rejected load — a rejection is a data
# point, not an error. The host-side comparator (check-results.sh) decides
# pass/fail by comparing these results against each example's declared
# minimum kernel. This script's only hard failures are setup problems
# (missing bpftool, missing object dir).
#
# Usage (inside guest): in-guest-load.sh <obj-dir> <results-json-out>
#   <obj-dir>          directory containing <stem>.bpf.o files (mounted)
#   <results-json-out> path to write the results JSON
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
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# Emit a JSON document: {kernel_release, results:[{object,loaded,log}]}.
# Built by hand (no jq dependency assumed in the guest).
json_escape() { python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null \
    || sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' | sed -e 's/^/"/' -e 's/$/"/'; }

printf '{\n  "kernel_release": "%s",\n  "results": [\n' "$KREL" > "$OUT"
first=1
shopt -s nullglob
for obj in "$OBJ_DIR"/*.bpf.o; do
    stem="$(basename "$obj" .bpf.o)"
    rm -rf "$PIN_BASE" 2>/dev/null || true
    # loadall exercises the verifier on every program in the object.
    log="$(bpftool prog loadall "$obj" "$PIN_BASE" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then loaded=true; logfield=""; else loaded=false; logfield="$log"; fi
    rm -rf "$PIN_BASE" 2>/dev/null || true

    [ "$first" -eq 1 ] || printf ',\n' >> "$OUT"
    first=0
    printf '    {"object": "%s", "loaded": %s, "log": %s}' \
        "$stem" "$loaded" "$(printf '%s' "$logfield" | json_escape)" >> "$OUT"
    echo "load $stem: rc=$rc loaded=$loaded"
done
printf '\n  ]\n}\n' >> "$OUT"

echo "--- results written to $OUT ---"
cat "$OUT"
