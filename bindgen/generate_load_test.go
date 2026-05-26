// Tests for LoadObjects behavior and nil-safety of generated bindings.
// Roadmap: #18.
//
// The runtime behavior tests (nil-field Close, ctx-cancel ringbuf unwind) live
// in the generated fixture package under testdata/generated/openwatch/ so they
// run against the actual generated types. This file anchors them in the bindgen
// package by:
//   1. Verifying the fixture file matches what Generate() produces today
//      (drift detection — fails fast when the template changes but the
//      fixture is not regenerated).
//   2. Documenting the intent so the test suite's purpose is clear.

package bindgen

import (
	"os"
	"strings"
	"testing"

	"m31labs.dev/horizon/ir"
)

// openWatchProgram is the ir.Program that produced the openwatch golden output.
// It mirrors examples/openwatch/open.hzn.
var openWatchProgram = ir.Program{
	Package: "probes",
	Structs: []ir.Struct{{
		Name: "OpenEvent",
		Fields: []ir.Field{
			{Name: "pid", Type: ir.Type{Name: "u32"}},
			{Name: "uid", Type: ir.Type{Name: "u32"}},
			{Name: "comm", Type: ir.Type{Len: "16", Elem: &ir.Type{Name: "u8"}}},
			{Name: "path", Type: ir.Type{Len: "256", Elem: &ir.Type{Name: "u8"}}},
		},
	}},
	Maps: []ir.Map{{
		Name: "OpenEvents",
		Kind: ir.MapKindRingbuf,
		Val:  ir.Type{Name: "OpenEvent"},
	}},
	Functions: []ir.Function{{
		Name: "OnOpen",
		Section: ir.Section{
			Kind:   ir.ProgramKprobe,
			Attach: "do_sys_openat2",
			Name:   "kprobe/do_sys_openat2",
		},
	}},
	Capabilities: []ir.Capability{{
		Name:    "kernel.file.open.observe",
		Kind:    ir.CapabilitySource,
		Danger:  ir.DangerObserve,
		Program: "OnOpen",
		Section: "kprobe/do_sys_openat2",
		Emits:   "OpenEvent",
		Maps: ir.CapabilityMapAccess{
			Events: []string{"OpenEvents"},
		},
	}},
}

// TestGeneratedObjectsCloseSurvivesNilFields_FixtureMatchesGenerator verifies
// that the fixture bindings used by the runtime behavior tests match the current
// generator output. If this test fails, regenerate the fixture with:
//
//	go run ./cmd/hzn gen examples/openwatch/open.hzn
//	cp <output> bindgen/testdata/generated/openwatch/bindings.go
//
// The runtime behavior tests themselves are in:
//
//	bindgen/testdata/generated/openwatch/bindings_behavior_test.go
func TestGeneratedObjectsCloseSurvivesNilFields_FixtureMatchesGenerator(t *testing.T) {
	generated, err := Generate(openWatchProgram, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	fixtureBytes, err := os.ReadFile("testdata/generated/openwatch/bindings.go")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fixture := string(fixtureBytes)

	if generated != fixture {
		// Find the first differing line for a useful failure message.
		genLines := strings.Split(generated, "\n")
		fixLines := strings.Split(fixture, "\n")
		for i := 0; i < len(genLines) && i < len(fixLines); i++ {
			if genLines[i] != fixLines[i] {
				t.Fatalf("fixture diverges from generator at line %d:\n  fixture:   %q\n  generated: %q\n\nRegenerate with: go run ./cmd/hzn gen examples/openwatch/open.hzn", i+1, fixLines[i], genLines[i])
			}
		}
		t.Fatalf("fixture has %d lines, generator produces %d lines; regenerate the fixture", len(fixLines), len(genLines))
	}
}

// TestGeneratedCloseTemplateNilGuards verifies that the emitClose template
// emits nil guards for every field. This is a fast in-process check that
// complements the runtime Close() tests in the fixture package.
func TestGeneratedCloseTemplateNilGuards(t *testing.T) {
	prog := ir.Program{
		Maps: []ir.Map{
			{Name: "events", Kind: ir.MapKindRingbuf, Val: ir.Type{Name: "Event"}},
			{Name: "counts", Kind: ir.MapKindHash, Key: ir.Type{Name: "u32"}, Val: ir.Type{Name: "u64"}},
		},
		Functions: []ir.Function{{
			Name:    "OnExec",
			Section: ir.Section{Kind: ir.ProgramTracepoint, Attach: "sched:sched_process_exec"},
		}},
	}
	code, err := Generate(prog, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, field := range []string{"Events", "Counts", "OnExec"} {
		guard := "if o." + field + " != nil {"
		if !strings.Contains(code, guard) {
			t.Errorf("emitClose missing nil guard for field %s; want %q\n%s", field, guard, code)
		}
	}
	// Also verify the nil receiver guard.
	if !strings.Contains(code, "if o == nil {") {
		t.Errorf("emitClose missing nil receiver guard\n%s", code)
	}
}

// TestGeneratedRingbufReaderCtxCancelTemplate verifies that the emitRingbufReader
// template emits the context-cancellation plumbing. This is a fast string check;
// the full runtime unwind test is in the fixture package.
func TestGeneratedRingbufReaderCtxCancelTemplate(t *testing.T) {
	prog := ir.Program{
		Structs: []ir.Struct{{
			Name:   "Event",
			Fields: []ir.Field{{Name: "pid", Type: ir.Type{Name: "u32"}}},
		}},
		Maps: []ir.Map{{
			Name: "Events",
			Kind: ir.MapKindRingbuf,
			Val:  ir.Type{Name: "Event"},
		}},
	}
	code, err := Generate(prog, "bindings")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		"done := make(chan struct{})",
		"defer close(done)",
		"case <-ctx.Done():",
		"_ = reader.Close()",
		"if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {",
		"return ctx.Err()",
	} {
		if !strings.Contains(code, want) {
			t.Errorf("emitRingbufReader missing ctx-cancel plumbing %q\n%s", want, code)
		}
	}
}
