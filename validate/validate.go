package validate

import (
	"fmt"
	"os"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

func Program(program ir.Program) []diag.Diagnostic {
	sites := Collect(program)
	// Build the user-helper effect summary once per program. Each validator
	// that tracks a nullable resource (ringbuf today; maps/packet in later
	// Phase 2 #13 tasks) consults this summary to propagate caller-side
	// state across user-helper call sites. Cost is one walk per user helper.
	effects := BuildHelperEffects(program)
	var diags []diag.Diagnostic
	diags = append(diags, AnalyzeLoops(program, sites)...)
	diags = append(diags, AnalyzeStack(program, sites)...)
	diags = append(diags, AnalyzeRingbuf(program, sites, effects)...)
	diags = append(diags, AnalyzeMaps(program, sites, effects)...)
	diags = append(diags, AnalyzeHelpers(program, sites)...)
	diags = append(diags, AnalyzePacket(program, sites, effects)...)
	diags = append(diags, ValidateCapabilities(program)...)
	// #8 depth-telemetry env-gate. When HORIZON_BIRCH_DEPTH_REPORT is set,
	// emit one stderr line per program with the max helper-call-chain depth,
	// the helper count, and the per-call-site specialization cache overflow
	// count. Lives at the end of Program so the cache-overflow counter
	// reflects everything the validators consumed during this run. The
	// `make depth-report` Makefile target greps these lines and computes
	// the global max across HZN_EXAMPLES — see the plan's Step 6.4 cap
	// revisit policy.
	if os.Getenv("HORIZON_BIRCH_DEPTH_REPORT") != "" {
		name := program.Package
		if name == "" {
			name = "<unnamed>"
		}
		fmt.Fprintf(os.Stderr,
			"[birch-depth] program=%s max_depth=%d helper_count=%d cache_overflows=%d\n",
			name, effects.MaxObservedDepth, len(effects.byName), effects.CacheOverflows(),
		)
	}
	return diags
}
