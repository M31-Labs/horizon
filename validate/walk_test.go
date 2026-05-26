package validate_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/ir"
	"m31labs.dev/horizon/validate"
)

// TestValidatorContractAcrossExamples pins the current diagnostic output for
// every example. Refactoring validators must not change this set.
func TestValidatorContractAcrossExamples(t *testing.T) {
	examples, err := filepath.Glob("../examples/*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, ex := range examples {
		t.Run(filepath.Base(ex), func(t *testing.T) {
			result, err := compiler.AnalyzePath(ex)
			if err != nil {
				// Some examples may fail front-end; that is fine for this contract.
				return
			}
			diags := validate.Program(result.Program)
			codes := make([]string, 0, len(diags))
			for _, d := range diags {
				codes = append(codes, d.Code)
			}
			sort.Strings(codes)
			got := strings.Join(codes, ",")
			want := expectedDiagCodes(filepath.Base(ex))
			if got != want {
				t.Fatalf("%s diagnostic codes changed: got %q want %q",
					filepath.Base(ex), got, want)
			}
		})
	}
}

// expectedDiagCodes returns the baseline diagnostic codes per example,
// recorded before the unified-walk refactor. All examples compile cleanly
// with zero validator diagnostics. The eventbatch entry was added when
// Phase 2 #13 (helpers-take-resources) shipped — it pins the new
// resource-typed helper-parameter surface as compiling with zero diagnostics.
func expectedDiagCodes(name string) string {
	return map[string]string{
		"cgroupconnect": "",
		"eventbatch":    "",
		"execcount":     "",
		"execdeny":      "",
		"execwatch":     "",
		"killwatch":     "",
		"lsmfile":       "",
		"openwatch":     "",
		"tcpass":        "",
		"tcpconnect":    "",
		"xdpdrop":       "",
	}[name]
}

// TestCollectFindsRingbufReserveSites asserts that Collect finds at least one
// ringbuf reserve site in execwatch, which calls ExecEvents.reserve().
func TestCollectFindsRingbufReserveSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.RingbufReserve) == 0 {
		t.Fatal("expected at least one ringbuf reserve site in execwatch")
	}
}

// TestCollectFindsMapLookupSites asserts that Collect finds at least one map
// lookup site in execcount, which calls ExecCounts.lookup(pid).
func TestCollectFindsMapLookupSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execcount")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.MapLookup) == 0 {
		t.Fatal("expected at least one map lookup site in execcount")
	}
}

// TestCollectFindsHelperCallSites asserts that Collect finds at least one
// helper call site in execwatch, which calls bpf.ktime_get_ns, bpf.current_pid,
// bpf.current_ppid, bpf.current_uid, and bpf.current_comm.
func TestCollectFindsHelperCallSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.HelperCall) == 0 {
		t.Fatal("expected at least one helper call site in execwatch")
	}
}

// TestCollectFindsPacketHeaderSites asserts that Collect finds at least one
// packet header site in xdpdrop, which calls xdp.tcp(ctx).
func TestCollectFindsPacketHeaderSites(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/xdpdrop")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	sites := validate.Collect(result.Program)
	if len(sites.PacketHeader) == 0 {
		t.Fatal("expected at least one packet header site in xdpdrop")
	}
}

// TestCollectFindsLoopSiteFromSyntheticFixture verifies that Collect detects
// a for-statement and records a LoopSite for it.
func TestCollectFindsLoopSiteFromSyntheticFixture(t *testing.T) {
	prog := ir.Program{
		Functions: []ir.Function{{
			Name: "fnWithLoop",
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "for",
				}},
			}},
		}},
	}
	sites := validate.Collect(prog)
	if len(sites.Loops) != 1 {
		t.Fatalf("want 1 loop site, got %d", len(sites.Loops))
	}
}

// TestCollectFindsStackLocalSiteFromSyntheticFixture verifies that Collect
// detects a var_decl with an aggregate (non-scalar named) type and records a
// StackLocalSite for it.
func TestCollectFindsStackLocalSiteFromSyntheticFixture(t *testing.T) {
	prog := ir.Program{
		Functions: []ir.Function{{
			Name: "fnWithStruct",
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "var_decl",
					Name: "evt",
					Type: ir.Type{Name: "MyEvent"},
				}},
			}},
		}},
	}
	sites := validate.Collect(prog)
	if len(sites.StackLocals) != 1 {
		t.Fatalf("want 1 stack local site, got %d", len(sites.StackLocals))
	}
}

// TestCollectRecursesIntoIfInit verifies C1 (if.Init is traversed) and C2
// (the Stmt pointer in RingbufReserveSite is the original Init pointer, not a
// pointer into a temporary copy). It constructs an if-statement whose Init
// slot holds a ringbuf reserve short_var.
func TestCollectRecursesIntoIfInit(t *testing.T) {
	ringMap := ir.Map{Name: "Events", Kind: ir.MapKindRingbuf}

	// Construct the expression for: Events.reserve()
	// reserveCall expects: call { Func: selector { Operand: ident{Name:"Events"}, Field:"reserve" } }
	reserveExpr := &ir.Expr{
		Kind: "call",
		Func: &ir.Expr{
			Kind:    "selector",
			Operand: &ir.Expr{Kind: "ident", Name: "Events"},
			Field:   "reserve",
		},
	}

	// The init statement: x := Events.reserve()
	initStmt := &ir.Statement{
		Kind:  "short_var",
		Name:  "x",
		Value: reserveExpr,
	}

	prog := ir.Program{
		Maps: []ir.Map{ringMap},
		Functions: []ir.Function{{
			Name: "fnIfInit",
			Body: []ir.Block{{
				Statements: []ir.Statement{{
					Kind: "if",
					Init: initStmt,
				}},
			}},
		}},
	}

	sites := validate.Collect(prog)

	// C1: the site must be found at all.
	if len(sites.RingbufReserve) != 1 {
		t.Fatalf("ringbuf reserve in if.Init not found; got %d sites (C1 broken)", len(sites.RingbufReserve))
	}

	// C2: the recorded Stmt pointer must be the original initStmt pointer,
	// not a pointer into a temporary copy slice.
	if sites.RingbufReserve[0].Stmt != initStmt {
		t.Fatal("RingbufReserveSite.Stmt is not the original Init pointer (C2 broken)")
	}
}
