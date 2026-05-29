#!/usr/bin/env bash
# scripts/kernel-matrix/testdata/floor-check-test.sh
#
# Self-contained smoke test for the A3 min_kernel regression-guard
# (scripts/kernel-matrix/check-min-kernel.sh). Exercises the cross-kernel
# floor check against synthetic multi-kernel results fixtures so the logic is
# verifiable without booting a VM — matching the existing Python-in-shell
# comparator idiom rather than introducing a new test framework.
#
# Two fixtures under this directory:
#   floor-mismatch/ — a deliberate floor-too-low example (floorlow, loads
#                     below its declared 6.1 floor) and a floor-too-high
#                     example (floorhigh, fails until 6.6 despite a declared
#                     5.10 floor), plus a clean example (cleanexample) that
#                     must NOT be flagged.
#   floor-clean/    — every example's observed floor equals its declared
#                     min_kernel; the guard must pass clean (exit 0).
#
# Usage: bash scripts/kernel-matrix/testdata/floor-check-test.sh
# Exit 0 iff every assertion holds.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/../check-min-kernel.sh"
IMAGES="$SCRIPT_DIR/images.json"

fails=0
note() { printf '  %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; fails=$((fails + 1)); }

# --- Fixture 1: mismatch — guard must fail and name the two bad examples ---
MM="$SCRIPT_DIR/floor-mismatch"
out="$(bash "$GUARD" "$MM/cells" "$MM/reports" "$IMAGES" 2>&1)"; rc=$?
echo "$out"
if [ "$rc" -eq 0 ]; then
    fail "floor-mismatch fixture: guard exited 0, expected non-zero (mismatches present)"
else
    note "floor-mismatch fixture: guard exited $rc (non-zero) as expected"
fi
if ! grep -q 'floorlow' <<<"$out"; then
    fail "floor-mismatch fixture: 'floorlow' (loads below declared floor) not reported"
fi
if ! grep -q 'floorhigh' <<<"$out"; then
    fail "floor-mismatch fixture: 'floorhigh' (fails at/above declared floor) not reported"
fi
# A mismatch on a required kernel (6.1) must surface as a GitHub error.
if ! grep -q '::error::' <<<"$out"; then
    fail "floor-mismatch fixture: expected a ::error:: for a required-kernel mismatch"
fi
# The clean example must never be flagged as a mismatch.
if grep -E 'MISMATCH .*cleanexample|cleanexample.*MISMATCH' <<<"$out" >/dev/null; then
    fail "floor-mismatch fixture: 'cleanexample' was wrongly flagged as a mismatch"
fi

# --- Fixture 2: clean — guard must pass with no errors ---
CL="$SCRIPT_DIR/floor-clean"
out="$(bash "$GUARD" "$CL/cells" "$CL/reports" "$IMAGES" 2>&1)"; rc=$?
echo "$out"
if [ "$rc" -ne 0 ]; then
    fail "floor-clean fixture: guard exited $rc, expected 0 (no mismatches)"
else
    note "floor-clean fixture: guard exited 0 as expected"
fi
if grep -q '::error::' <<<"$out"; then
    fail "floor-clean fixture: unexpected ::error:: on a clean fixture"
fi

if [ "$fails" -ne 0 ]; then
    printf '\n%d assertion(s) failed\n' "$fails"
    exit 1
fi
printf '\nall floor-check assertions passed\n'
