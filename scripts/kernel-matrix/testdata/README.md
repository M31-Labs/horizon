# kernel-matrix testdata — min_kernel floor-check fixtures

Synthetic, VM-free fixtures for the A3 min_kernel regression-guard
(`scripts/kernel-matrix/check-min-kernel.sh`). They let the cross-kernel
floor-check logic be exercised without booting an LVH guest, matching the
existing Python-in-shell comparator idiom.

## Run the smoke test

```sh
bash scripts/kernel-matrix/testdata/floor-check-test.sh
```

Exit 0 iff every assertion holds.

## Layout

Each fixture mirrors a whole boot-matrix run:

```
<fixture>/
  reports/<stem>.report.json   # carries summary.min_kernel (the declared floor)
  cells/<kernel>/results.json   # in-guest-load.sh output for that kernel cell
```

`images.json` (in this directory) is the synthetic gate map — it mirrors the
real `scripts/kernel-matrix/images.json` gate assignments (5.10/5.15
best_effort, 6.1/6.6 required) but carries no image versions or digests, since
the floor check never boots a VM.

## Fixtures

### `floor-mismatch/`

Three examples, exercising both mismatch directions plus the clean control:

| example        | declared | 5.10 | 5.15 | 6.1 | 6.6 | observed floor | verdict |
|----------------|----------|------|------|-----|-----|----------------|---------|
| `cleanexample` | 5.15     | ✗    | ✓    | ✓   | ✓   | 5.15           | clean (declared == observed) |
| `floorlow`     | 6.1      | ✓    | ✓    | ✓   | ✓   | 5.10           | MISMATCH — loads BELOW declared floor (only on best-effort 5.10/5.15 → `::warning::`) |
| `floorhigh`    | 5.10     | ✗    | ✗    | ✗   | ✓   | 6.6            | MISMATCH — FAILS at/above declared floor (incl. required 6.1 → `::error::`) |

The guard must exit non-zero (a required-kernel mismatch is present), flag
`floorlow` and `floorhigh`, and leave `cleanexample` unflagged.

### `floor-clean/`

Every example's observed floor equals its declared `min_kernel`; the guard
must pass clean (exit 0, no `::error::`).

| example | declared | 5.10 | 5.15 | 6.1 | 6.6 | observed floor |
|---------|----------|------|------|-----|-----|----------------|
| `alpha` | 5.10     | ✓    | ✓    | ✓   | ✓   | 5.10           |
| `beta`  | 6.1      | ✗    | ✗    | ✓   | ✓   | 6.1            |
