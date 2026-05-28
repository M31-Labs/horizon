package compiler

import (
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/horizon/capability"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/internal/registry"
)

// TestExampleManifestsValidateAgainstRegistry compiles every example
// in examples/ and asserts each emitted Capability's name + program
// kind + attach matches a registry entry, and the capability's leaf
// is in the entry's allowed_danger_leaves.
//
// Emit-side half of the bidirectional contract test from
// spec.horizon-continuum-integration.v1 §A.4. The Continuum-side half
// lives in plan.continuum.horizon-schema-v1.
func TestExampleManifestsValidateAgainstRegistry(t *testing.T) {
	r := registry.MustLoad()
	examples, err := filepath.Glob("../examples/*")
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(examples) == 0 {
		t.Fatalf("no examples found")
	}

	for _, dir := range examples {
		dir := dir
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			// remoteimport-execcount imports a fixture from the
			// in-repo testdata cache. Point HORIZON_CACHE_ROOT at
			// the abs path of testdata/remote-fixtures so the
			// resolver finds the fixture (cache hit) instead of
			// trying to clone from github. See
			// docs/internal/remote-imports-testing.md.
			if name == "remoteimport-execcount" {
				abs, err := filepath.Abs("../testdata/remote-fixtures")
				if err != nil {
					t.Fatalf("abs remote-fixtures: %v", err)
				}
				t.Setenv("HORIZON_CACHE_ROOT", abs)
			}
			result, err := AnalyzePath(dir)
			if err != nil {
				t.Fatalf("analyze %s: %v", dir, err)
			}
			if diag.HasErrors(result.Diagnostics) {
				t.Fatalf("analyze %s produced diagnostics: %v", dir, result.Diagnostics)
			}
			manifest := capability.FromIR(result.Program)
			for _, cap := range manifest.Capabilities {
				if !strings.HasPrefix(cap.Name, "kernel.") {
					continue // non-kernel namespaces are out of registry scope
				}
				validateCapabilityAgainstRegistry(t, r, manifest, cap)
			}
		})
	}
}

func validateCapabilityAgainstRegistry(t *testing.T, r registry.Registry, manifest capability.Manifest, cap capability.Capability) {
	t.Helper()
	// Find the program this capability attaches to.
	var prog *capability.Program
	for i := range manifest.Programs {
		if manifest.Programs[i].Name == cap.Program {
			prog = &manifest.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Errorf("capability %q references unknown program %q", cap.Name, cap.Program)
		return
	}

	// Find matching registry entry.
	var matched *registry.Namespace
	for i := range r.Namespaces {
		ns := &r.Namespaces[i]
		if ns.AttachSurface != prog.Kind {
			continue
		}
		if len(ns.AttachStrings) > 0 {
			hit := false
			for _, att := range ns.AttachStrings {
				if att == prog.Attach {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if !strings.HasPrefix(cap.Name, ns.Namespace+".") {
			continue
		}
		matched = ns
		break
	}

	if matched == nil {
		t.Errorf("capability %q on program %q (%s/%s) has no matching registry entry", cap.Name, cap.Program, prog.Kind, prog.Attach)
		return
	}

	// Extract leaf and verify it's in allowed_danger_leaves.
	leaf := cap.Name
	for {
		_, rest, ok := strings.Cut(leaf, ".")
		if !ok {
			break
		}
		leaf = rest
	}
	for _, allowed := range matched.AllowedDangerLeaves {
		if allowed == leaf {
			return // OK
		}
	}
	t.Errorf("capability %q has leaf %q not in registry's allowed_danger_leaves %v for (%s, %v)", cap.Name, leaf, matched.AllowedDangerLeaves, matched.AttachSurface, matched.AttachStrings)
}
