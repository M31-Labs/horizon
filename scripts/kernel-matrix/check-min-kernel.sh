#!/usr/bin/env bash
# scripts/kernel-matrix/check-min-kernel.sh
#
# A3 min_kernel regression-guard (cross-kernel floor check).
#
# The per-cell comparator (check-results.sh) validates, for ONE kernel, that
# each example's load outcome matches `kernel >= declared min_kernel`. This
# aggregator looks ACROSS the whole boot matrix: for each example it computes
# the OBSERVED verifier floor — the lowest matrix kernel on which the object
# actually loaded — and compares it against the example's DECLARED
# `summary.min_kernel`. A drift between the two is a regression:
#
#   * floor-too-low  — the object loads on a kernel BELOW its declared floor
#                      (the declared min_kernel is stricter than reality).
#   * floor-too-high — the object FAILS on a kernel AT/ABOVE its declared
#                      floor (the declared min_kernel is too optimistic).
#
# This is a regression-GUARD only: it never derives, rewrites, or suggests a
# min_kernel value (spec O-4 — auto-derivation is out of scope). It only flags
# the mismatch so a human updates the declared floor (or the codegen).
#
# Gate semantics mirror the existing comparator: a mismatch that manifests on
# a REQUIRED kernel (per images.json `gate`) is a `::error::` and fails the
# workflow; a mismatch confined to best-effort kernels is a `::warning::`.
#
# Inputs:
#   <cells-dir>    directory with one subdir per kernel; each holds a
#                  results.json ({kernel_release, results:[{object, loaded}]})
#                  as written by in-guest-load.sh. The subdir NAME is the
#                  kernel version key (e.g. "6.1") used to look up the gate.
#   <reports-dir>  directory of <stem>.report.json carrying summary.min_kernel
#                  (the co-located build artifacts).
#   [images-json]  gate map (default: sibling images.json). Supplies each
#                  kernel's `gate` (required | best_effort).
#
# Usage: check-min-kernel.sh <cells-dir> <reports-dir> [images-json]
# Exit 0 if every example is floor-consistent (or only best-effort
# mismatches); non-zero on any required-kernel floor mismatch.
set -uo pipefail

CELLS_DIR="${1:?usage: check-min-kernel.sh <cells-dir> <reports-dir> [images-json]}"
REPORTS_DIR="${2:?usage: check-min-kernel.sh <cells-dir> <reports-dir> [images-json]}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_JSON="${3:-$SCRIPT_DIR/images.json}"

python3 - "$CELLS_DIR" "$REPORTS_DIR" "$IMAGES_JSON" <<'PY'
import json, sys, glob, os

cells_dir, reports_dir, images_path = sys.argv[1], sys.argv[2], sys.argv[3]

def ver(s):
    # "5.10" -> (5,10); tolerate patch and junk. Identical to check-results.sh.
    out = []
    for part in str(s).split('.')[:2]:
        num = ''.join(c for c in part if c.isdigit())
        out.append(int(num) if num else 0)
    while len(out) < 2:
        out.append(0)
    return tuple(out)

# --- gate map: kernel-version-key -> "required" | "best_effort" ---
with open(images_path) as f:
    images = json.load(f)
gate_of = {img["kernel"]: img.get("gate", "best_effort")
           for img in images.get("images", [])}

# --- declared floors: stem -> declared min_kernel string ---
reports = sorted(glob.glob(os.path.join(reports_dir, "*.report.json")))
if not reports:
    print(f"::error::no *.report.json under {reports_dir}", file=sys.stderr)
    sys.exit(2)
declared = {}
for rp in reports:
    stem = os.path.basename(rp)[:-len(".report.json")]
    with open(rp) as f:
        rep = json.load(f)
    declared[stem] = rep.get("summary", {}).get("min_kernel", "0.0")

# --- per-cell load outcomes: kernel-key -> {stem: bool} ---
cells = {}
for entry in sorted(os.listdir(cells_dir)):
    rj = os.path.join(cells_dir, entry, "results.json")
    if not os.path.isfile(rj):
        continue
    with open(rj) as f:
        res = json.load(f)
    cells[entry] = {r["object"]: bool(r["loaded"])
                    for r in res.get("results", [])}

if not cells:
    print(f"::error::no <kernel>/results.json cells under {cells_dir}",
          file=sys.stderr)
    sys.exit(2)

# Sorted kernel keys low -> high, by version tuple.
kernels = sorted(cells.keys(), key=ver)

required_mismatches = 0
besteffort_mismatches = 0
checked = 0

for stem in sorted(declared):
    dec = declared[stem]
    dver = ver(dec)
    # Which kernels did this object load on? Only consider cells that
    # actually carried a result for the object.
    present = [k for k in kernels if stem in cells[k]]
    if not present:
        print(f"  SKIP {stem}: no load result in any cell")
        continue
    checked += 1

    loaded_on = [k for k in present if cells[k][stem]]
    observed_floor = min(loaded_on, key=ver) if loaded_on else None

    # floor-too-low: any kernel BELOW the declared floor on which it loaded.
    below = [k for k in loaded_on if ver(k) < dver]
    # floor-too-high: any kernel AT/ABOVE the declared floor on which it FAILED.
    above_fail = [k for k in present if ver(k) >= dver and not cells[k][stem]]

    bad_kernels = sorted(set(below) | set(above_fail), key=ver)
    if not bad_kernels:
        of = observed_floor if observed_floor is not None else "(never loaded)"
        print(f"  ok {stem}: declared_min_kernel={dec} observed_floor={of} "
              f"(loaded_on={loaded_on or 'none'})")
        continue

    # A mismatch is required-gated iff it manifests on any required kernel.
    req_hit = [k for k in bad_kernels if gate_of.get(k) == "required"]
    severity = "error" if req_hit else "warning"
    if req_hit:
        required_mismatches += 1
    else:
        besteffort_mismatches += 1

    of = observed_floor if observed_floor is not None else "(never loaded)"
    reasons = []
    if below:
        reasons.append("loads below declared floor on " + ",".join(below))
    if above_fail:
        reasons.append("fails at/above declared floor on " + ",".join(above_fail))
    detail = "; ".join(reasons)
    print(f"  MISMATCH {stem}: declared_min_kernel={dec} "
          f"observed_floor={of} ({detail})")
    print(f"::{severity}::min_kernel floor mismatch for {stem}: "
          f"declared {dec} but observed floor {of} "
          f"[{detail}] — update the declared summary.min_kernel "
          f"(regression-guard only; no auto-derivation)")

print(f"--- min_kernel floor check: {checked} example(s), "
      f"{required_mismatches} required mismatch(es), "
      f"{besteffort_mismatches} best-effort mismatch(es) ---")
sys.exit(1 if required_mismatches else 0)
PY
