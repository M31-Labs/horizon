package compiler

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

func CollectFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Skip well-known non-source directories. `vendor` is excluded so
			// CollectFiles never accidentally folds an imported package's
			// source into the importing package's CheckPackage call — those
			// files belong to the importer's dependency graph, walked by
			// ResolveImports instead.
			if name == ".git" || name == "dist" || name == "generated" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".hzn") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .hzn files found in %s", root)
	}
	return paths, nil
}
