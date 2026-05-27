package capability

import (
	"bytes"
	"encoding/json"
	"testing"

	"m31labs.dev/horizon/compiler/diag"
)

// TestAggregateRootOnlyPreservesBareNames verifies that AggregateManifests
// returns root-package capabilities unchanged when there are no imported
// manifests in play. Names stay bare; Origin stays empty. Per roadmap #21
// Phase 2 Subtask 5a: bare-name preservation is the default invariant for
// single-package builds even when they happen to be routed through the
// aggregator.
func TestAggregateRootOnlyPreservesBareNames(t *testing.T) {
	root := NewManifest("probes")
	root.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
	}}
	got, diags := AggregateManifests([]Manifest{root}, "probes")
	if hasErrorDiag(diags) {
		t.Fatalf("AggregateManifests root-only produced error diagnostics: %#v", diags)
	}
	if len(got.Capabilities) != 1 {
		t.Fatalf("AggregateManifests Capabilities len = %d, want 1", len(got.Capabilities))
	}
	if got.Capabilities[0].Name != "ExecObserve" {
		t.Fatalf("root-only Name = %q, want %q", got.Capabilities[0].Name, "ExecObserve")
	}
	if got.Capabilities[0].Origin != "" {
		t.Fatalf("root-only Origin = %q, want empty", got.Capabilities[0].Origin)
	}
}

// TestAggregateQualifiesImportedCapabilities verifies that a capability
// declared in an imported package is renamed with the import alias as a
// qualifier (e.g. ExecObserve -> events.ExecObserve) and that the Origin
// field records the alias. Root-package capabilities are unaffected.
func TestAggregateQualifiesImportedCapabilities(t *testing.T) {
	root := NewManifest("probes")
	root.Capabilities = []Capability{{
		Name:    "RootCap",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
	}}
	events := NewManifest("events")
	events.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "events",
	}}
	got, diags := AggregateManifests([]Manifest{root, events}, "probes")
	if hasErrorDiag(diags) {
		t.Fatalf("AggregateManifests produced error diagnostics: %#v", diags)
	}
	byName := map[string]Capability{}
	for _, c := range got.Capabilities {
		byName[c.Name] = c
	}
	if _, ok := byName["RootCap"]; !ok {
		t.Fatalf("expected root capability RootCap with bare name; got %+v", got.Capabilities)
	}
	if byName["RootCap"].Origin != "" {
		t.Fatalf("RootCap Origin = %q, want empty", byName["RootCap"].Origin)
	}
	qualified, ok := byName["events.ExecObserve"]
	if !ok {
		t.Fatalf("expected qualified capability events.ExecObserve; got %+v", got.Capabilities)
	}
	if qualified.Origin != "events" {
		t.Fatalf("events.ExecObserve Origin = %q, want %q", qualified.Origin, "events")
	}
}

// TestAggregateRejectsConflictingCapabilityValues verifies that when two
// manifests declare the same qualified capability name but disagree on the
// underlying danger or section, AggregateManifests surfaces an HZN1560
// error diagnostic. Same-package multi-file conflicts remain
// types.CheckPackage's responsibility, so this test pins behavior only for
// cross-package collisions where Origin disambiguates ownership.
func TestAggregateRejectsConflictingCapabilityValues(t *testing.T) {
	a := NewManifest("events")
	a.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "events",
	}}
	b := NewManifest("events")
	b.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "mutate", Scope: "process", Reversibility: "restart"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "events",
	}}
	_, diags := AggregateManifests([]Manifest{a, b}, "probes")
	if !hasDiagCode(diags, "HZN1560") {
		t.Fatalf("expected HZN1560 capability-value conflict; got %#v", diags)
	}
}

// TestAggregateDeduplicatesIdenticalCapabilities verifies that two
// manifests contributing the same capability (same qualified name, same
// danger, same program, same section) collapse to one entry without
// diagnostic.
func TestAggregateDeduplicatesIdenticalCapabilities(t *testing.T) {
	cap := Capability{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "events",
	}
	a := NewManifest("events")
	a.Capabilities = []Capability{cap}
	b := NewManifest("events")
	b.Capabilities = []Capability{cap}
	got, diags := AggregateManifests([]Manifest{a, b}, "probes")
	if hasErrorDiag(diags) {
		t.Fatalf("dedup produced error diagnostics: %#v", diags)
	}
	count := 0
	for _, c := range got.Capabilities {
		if c.Name == "events.ExecObserve" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("deduplicated capability count = %d, want 1; caps = %+v", count, got.Capabilities)
	}
}

// TestAggregateWarnsOnSharedCapabilityValueAcrossPackages verifies that
// when two distinct packages each declare a capability whose section value
// collides (the "two packages independently claiming the same kernel hook"
// case) AggregateManifests emits a HZN1553 warning. The warning is
// advisory — both qualified names remain in the manifest.
func TestAggregateWarnsOnSharedCapabilityValueAcrossPackages(t *testing.T) {
	a := NewManifest("events")
	a.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "events",
	}}
	b := NewManifest("audit")
	b.Capabilities = []Capability{{
		Name:    "ExecObserve",
		Kind:    "source",
		Danger:  DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec",
		Section: "tracepoint/sched:sched_process_exec",
		Origin:  "audit",
	}}
	_, diags := AggregateManifests([]Manifest{a, b}, "probes")
	found := false
	for _, d := range diags {
		if d.Code == "HZN1553" && d.Severity == diag.SeverityWarning {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected HZN1553 warning for shared capability value across packages; got %#v", diags)
	}
}

// TestAggregateRejectsConflictingMapShapes verifies that when two
// manifests contribute a map under the same qualified name but disagree
// on key/value/kind, AggregateManifests surfaces an HZN1566 error
// diagnostic.
//
// HZN1566 = manifest-aggregation map shape conflict (post-IR-merge);
// the IR-layer twin HZN1564 still fires at ir.MergeWithDiagnostics for
// struct-layout collisions detected before manifest aggregation runs.
func TestAggregateRejectsConflictingMapShapes(t *testing.T) {
	a := NewManifest("events")
	a.Maps = []Map{{Name: "Events", Kind: "ringbuf", Value: "ExecEvent"}}
	b := NewManifest("events")
	b.Maps = []Map{{Name: "Events", Kind: "hash", Key: "u32", Value: "u64"}}
	_, diags := AggregateManifests([]Manifest{
		mustOriginMaps(a, "events"),
		mustOriginMaps(b, "events"),
	}, "probes")
	if !hasDiagCode(diags, "HZN1566") {
		t.Fatalf("expected HZN1566 manifest-aggregation map shape conflict; got %#v", diags)
	}
}

// TestAggregateRejectsConflictingTypeSchemas verifies that when two
// manifests contribute a type schema with the same bare name but
// differing layouts (kind / size / fields), AggregateManifests surfaces
// an HZN1567 error diagnostic.
//
// HZN1567 = manifest-aggregation type schema conflict (post-IR-merge);
// the IR-layer twin HZN1565 still fires at ir.MergeWithDiagnostics for
// capability collisions detected before manifest aggregation runs.
func TestAggregateRejectsConflictingTypeSchemas(t *testing.T) {
	a := NewManifest("events")
	aSize := 8
	a.Types = []TypeSchema{{
		Name: "ExecEvent",
		Kind: "struct",
		Size: &aSize,
		Fields: []FieldSchema{
			{Name: "pid", Type: "u32"},
			{Name: "uid", Type: "u32"},
		},
	}}
	b := NewManifest("audit")
	bSize := 16
	b.Types = []TypeSchema{{
		Name: "ExecEvent",
		Kind: "struct",
		Size: &bSize,
		Fields: []FieldSchema{
			{Name: "pid", Type: "u64"},
			{Name: "tgid", Type: "u64"},
		},
	}}
	_, diags := AggregateManifests([]Manifest{a, b}, "probes")
	if !hasDiagCode(diags, "HZN1567") {
		t.Fatalf("expected HZN1567 manifest-aggregation type schema conflict; got %#v", diags)
	}
}

// TestAggregateIsDeterministic verifies that AggregateManifests produces
// byte-equal output when invoked repeatedly on the same inputs. This pins
// against any accidental introduction of map-iteration order leakage in
// the merging or sorting pipeline.
func TestAggregateIsDeterministic(t *testing.T) {
	root := NewManifest("probes")
	root.Capabilities = []Capability{{
		Name: "Z_RootLast", Kind: "source", Origin: "",
		Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec", Section: "tracepoint/sched:sched_process_exec",
	}, {
		Name: "A_RootFirst", Kind: "source", Origin: "",
		Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec", Section: "tracepoint/sched:sched_process_exec",
	}}
	root.Maps = []Map{
		{Name: "ZMap", Kind: "ringbuf", Value: "u8"},
		{Name: "AMap", Kind: "ringbuf", Value: "u8"},
	}
	dep := NewManifest("events")
	dep.Capabilities = []Capability{{
		Name: "B_DepCap", Kind: "source", Origin: "events",
		Danger: DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"},
		Program: "OnExec", Section: "tracepoint/sched:sched_process_exec",
	}}
	dep.Maps = []Map{{Name: "DepMap", Kind: "ringbuf", Value: "u8", Origin: "events"}}

	var first []byte
	for i := 0; i < 10; i++ {
		got, _ := AggregateManifests([]Manifest{root, dep}, "probes")
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("iter %d: json.Marshal: %v", i, err)
		}
		if i == 0 {
			first = encoded
			continue
		}
		if !bytes.Equal(first, encoded) {
			t.Fatalf("iter %d: aggregated output differs:\nfirst=%s\nnow  =%s", i, first, encoded)
		}
	}
}

// mustOriginMaps stamps Origin on every map in the manifest. Used in tests
// to simulate manifests that have already been routed through per-package
// lowering with origin tagging.
func mustOriginMaps(m Manifest, origin string) Manifest {
	for i := range m.Maps {
		m.Maps[i].Origin = origin
	}
	return m
}

func hasDiagCode(diags []diag.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

func hasErrorDiag(diags []diag.Diagnostic) bool {
	for _, d := range diags {
		if d.Severity == diag.SeverityError {
			return true
		}
	}
	return false
}
