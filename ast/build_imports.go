package ast

import "sort"

// GroupByPackage partitions a flat list of File values into Package
// aggregates, one per distinct `package <name>` declaration. Files lacking a
// package declaration are dropped (the type checker reports the missing-
// package diagnostic via the front-end path). Within each Package, Files are
// sorted by Span.File for determinism so downstream consumers (type checker,
// IR lowering, golden snapshots) see the same order regardless of how the
// caller assembled the input.
//
// The returned slice itself is sorted by Package.Name so iteration order is
// stable across runs.
func GroupByPackage(files []File) []Package {
	byName := map[string][]File{}
	for _, f := range files {
		if f.Package == "" {
			continue
		}
		byName[f.Package] = append(byName[f.Package], f)
	}
	out := make([]Package, 0, len(byName))
	for name, files := range byName {
		sort.SliceStable(files, func(i, j int) bool {
			return string(files[i].Span.File) < string(files[j].Span.File)
		})
		pkg := Package{Name: name, Files: files}
		if len(files) > 0 {
			pkg.Span = files[0].Span
		}
		out = append(out, pkg)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
