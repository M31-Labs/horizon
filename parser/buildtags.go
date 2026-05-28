// Package parser — build-tag scanning.
//
// ExtractBuildTags reads the leading contiguous comment block of a `.hzn`
// source file and pulls out any `//hzn:build <expr>` directives. Multiple
// directives are caller-ANDed (the matcher in `compiler/buildmatrix.go`
// joins them with `&&`). Scanning stops at the first non-comment,
// non-blank line — directives after the `package` clause are ignored.
//
// The scanner is intentionally permissive of leading whitespace (a
// `.hzn` file authored with a stray indent on the directive line still
// parses) and of non-directive comment lines (doc comments interleaved
// with directives do not break the scan). The directive prefix is
// `//hzn:build ` (note the trailing space) — `//hzn:buildx`-style
// pseudo-directives are skipped.
package parser

import (
	"bufio"
	"bytes"
	"strings"
)

const buildDirectivePrefix = "hzn:build "

// ExtractBuildTags returns the list of `//hzn:build <expr>` expressions
// declared in the leading comment block of source, in source order.
// Returns an empty slice when no directives are present.
func ExtractBuildTags(source []byte) []string {
	var tags []string
	scanner := bufio.NewScanner(bytes.NewReader(source))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break // first non-comment, non-blank line — stop scanning
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "//"))
		if !strings.HasPrefix(rest, buildDirectivePrefix) {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(rest, buildDirectivePrefix))
		if expr == "" {
			continue
		}
		tags = append(tags, expr)
	}
	return tags
}
