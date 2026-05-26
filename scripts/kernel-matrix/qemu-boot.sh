#!/usr/bin/env bash
# scripts/kernel-matrix/qemu-boot.sh
#
# Fetch (cache-by-sha) a qcow2 kernel image, boot under qemu, mount the
# bpf-obj-dir into the guest, run a guest-side smoke loader, capture
# per-example results.
#
# Usage: bash scripts/kernel-matrix/qemu-boot.sh <url> <sha256> <bpf-obj-dir>
# Exit 0 if every .bpf.o loads successfully inside the guest.
#
# TODO(#19 images): implementation stubbed until canned images publish.

set -euo pipefail

if [ $# -ne 3 ]; then
    echo "usage: $0 <url> <sha256> <bpf-obj-dir>" >&2
    exit 2
fi

URL="$1"
SHA="$2"
BPF_DIR="$3"

CACHE_DIR="${HOME}/.cache/horizon/kernel-images"
mkdir -p "$CACHE_DIR"
CACHED="${CACHE_DIR}/${SHA}.qcow2"

# TODO(#19 images): implement
#   - if cached file exists and sha256 matches, use it
#   - otherwise curl -fsSL "$URL" -o "$CACHED"; verify sha256; on mismatch, abort
#   - choose qemu accelerator: KVM if /dev/kvm exists and is writable, otherwise tcg
#   - launch qemu with: -drive file=$CACHED,format=qcow2 -append "console=ttyS0"
#                       -virtfs local,path=$BPF_DIR,mount_tag=bpfobjs,security_model=mapped
#                       -m 1024 -nographic -no-reboot
#   - guest cloud-init or init runs a tiny bpf-loader binary that iterates /bpfobjs/*.bpf.o,
#     loads each via cilium/ebpf, attaches its programs, sleeps 200ms, detaches, unloads,
#     prints "PASS <basename>" or "FAIL <basename>: <err>" to console
#   - capture serial output, grep for FAIL lines, exit non-zero if any

echo "::error::qemu-boot.sh stub — implementation pending #19 image publication" >&2
exit 78  # EX_CONFIG
