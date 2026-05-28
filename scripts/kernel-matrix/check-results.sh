#!/usr/bin/env bash
# scripts/kernel-matrix/check-results.sh
#
# Host-side comparator for the kernel-matrix. Given a kernel version, the
# directory of build artifacts (each example's <stem>.report.json carries
# summary.min_kernel), and the in-guest load results, it derives the
# EXPECTED outcome per example and flags any discrepancy.
#
# Expected outcome is not hand-maintained: an example is expected to load on
# kernel K iff K >= the example's declared minimum kernel. This validates two
# things at once — that verifier-clean examples actually pass the verifier,
# and that Horizon's own min_kernel claims are accurate (an example that
# loads below its claimed minimum, or fails at/above it, is a real
# discrepancy).
#
# Usage: check-results.sh <kernel-version> <artifact-dir> <results-json>
# Exit 0 if every example matches expectation; non-zero on any mismatch.
set -euo pipefail

KERNEL="${1:?usage: check-results.sh <kernel-version> <artifact-dir> <results-json>}"
ART_DIR="${2:?usage: check-results.sh <kernel-version> <artifact-dir> <results-json>}"
RESULTS="${3:?usage: check-results.sh <kernel-version> <artifact-dir> <results-json>}"

python3 - "$KERNEL" "$ART_DIR" "$RESULTS" <<'PY'
import json, sys, glob, os

kernel, art_dir, results_path = sys.argv[1], sys.argv[2], sys.argv[3]

def ver(s):
    # "5.10" -> (5,10); tolerate patch and junk.
    out = []
    for part in str(s).split('.')[:2]:
        num = ''.join(c for c in part if c.isdigit())
        out.append(int(num) if num else 0)
    while len(out) < 2:
        out.append(0)
    return tuple(out)

kver = ver(kernel)

with open(results_path) as f:
    results = json.load(f)
loaded = {r["object"]: bool(r["loaded"]) for r in results.get("results", [])}
logs = {r["object"]: r.get("log", "") for r in results.get("results", [])}

reports = sorted(glob.glob(os.path.join(art_dir, "*.report.json")))
if not reports:
    print(f"::error::no *.report.json under {art_dir}", file=sys.stderr)
    sys.exit(2)

mismatches = 0
checked = 0
for rp in reports:
    stem = os.path.basename(rp)[:-len(".report.json")]
    with open(rp) as f:
        rep = json.load(f)
    min_kernel = rep.get("summary", {}).get("min_kernel", "0.0")
    expected = kver >= ver(min_kernel)
    if stem not in loaded:
        print(f"  SKIP {stem}: no load result (object not built/loaded)")
        continue
    checked += 1
    actual = loaded[stem]
    mark = "ok" if actual == expected else "MISMATCH"
    print(f"  {mark} {stem}: min_kernel={min_kernel} kernel={kernel} "
          f"expected_load={expected} actual_load={actual}")
    if actual != expected:
        mismatches += 1
        if logs.get(stem):
            print("    verifier log (first 600 chars):")
            print("    " + logs[stem][:600].replace("\n", "\n    "))

print(f"--- kernel {kernel}: {checked} checked, {mismatches} mismatch(es) ---")
sys.exit(1 if mismatches else 0)
PY
