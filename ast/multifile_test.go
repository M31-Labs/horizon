package ast

import (
	"testing"

	"m31labs.dev/horizon/compiler/span"
)

func TestPackageAggregateGroupsFilesByName(t *testing.T) {
	files := []File{
		{
			Package: "events",
			Span:    span.Span{File: "a.hzn"},
		},
		{
			Package: "main",
			Span:    span.Span{File: "b.hzn"},
		},
		{
			Package: "events",
			Span:    span.Span{File: "c.hzn"},
		},
	}

	packages := GroupByPackage(files)
	if len(packages) != 2 {
		t.Fatalf("packages = %d, want 2; got %#v", len(packages), packages)
	}

	byName := map[string]Package{}
	for _, p := range packages {
		byName[p.Name] = p
	}

	events, ok := byName["events"]
	if !ok {
		t.Fatalf("missing events package; got %v", packageNames(packages))
	}
	if len(events.Files) != 2 {
		t.Fatalf("events.Files = %d, want 2", len(events.Files))
	}

	main, ok := byName["main"]
	if !ok {
		t.Fatalf("missing main package; got %v", packageNames(packages))
	}
	if len(main.Files) != 1 {
		t.Fatalf("main.Files = %d, want 1", len(main.Files))
	}
}

func TestPackageAggregateOrdersFilesStably(t *testing.T) {
	files := []File{
		{Package: "p", Span: span.Span{File: "c.hzn"}},
		{Package: "p", Span: span.Span{File: "a.hzn"}},
		{Package: "p", Span: span.Span{File: "b.hzn"}},
	}
	packages := GroupByPackage(files)
	if len(packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(packages))
	}
	got := []string{}
	for _, f := range packages[0].Files {
		got = append(got, string(f.Span.File))
	}
	want := []string{"a.hzn", "b.hzn", "c.hzn"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("files = %v, want %v (GroupByPackage must sort lexicographically for determinism)", got, want)
		}
	}
}

func TestPackageAggregateSkipsEmptyPackageDecl(t *testing.T) {
	files := []File{
		{Package: "", Span: span.Span{File: "broken.hzn"}},
		{Package: "p", Span: span.Span{File: "ok.hzn"}},
	}
	packages := GroupByPackage(files)
	if len(packages) != 1 {
		t.Fatalf("packages = %d, want 1 (files without a package decl are excluded)", len(packages))
	}
	if packages[0].Name != "p" {
		t.Fatalf("packages[0].Name = %q, want p", packages[0].Name)
	}
}

func packageNames(packages []Package) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.Name)
	}
	return out
}
