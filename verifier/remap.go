package verifier

import (
	"path/filepath"
	"strings"

	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

func Remap(log Log, sourceMap ir.SourceMap) []Diagnostic {
	return RemapWithGenerated(log, sourceMap, nil)
}

func RemapWithGenerated(log Log, sourceMap ir.SourceMap, generated []byte) []Diagnostic {
	if len(log.Entries) == 0 {
		if strings.TrimSpace(log.Raw) == "" {
			return nil
		}
		return []Diagnostic{{Message: strings.TrimSpace(log.Raw), Severity: "error", Raw: log.Raw}}
	}
	lines := generatedLines(generated)
	diags := make([]Diagnostic, 0, len(log.Entries))
	for _, entry := range log.Entries {
		diag := Diagnostic{
			Message:  entry.Message,
			Severity: entry.Severity,
			Raw:      entry.Raw,
			Kind:     entry.Kind,
		}
		if entry.Line > 0 {
			diag.Generated = span.Span{
				File:  span.FileID(entry.Path),
				Start: span.Point{Line: entry.Line, Column: entry.Column},
				End:   span.Point{Line: entry.Line, Column: entry.Column + 1},
			}
			if generatedMatches(entry.Path, sourceMap.Generated.Path) {
				mapping, ok, exact := mappingForGenerated(sourceMap, entry.Line, entry.Column)
				applySourceMapping(&diag, mapping, ok, exact)
			}
		}
		if diag.Span.IsZero() && entry.CSource != "" && len(lines) > 0 {
			if line := findGeneratedLine(lines, entry.CSource); line > 0 {
				diag.Generated = span.Span{
					File:  span.FileID(sourceMap.Generated.Path),
					Start: span.Point{Line: line, Column: 1},
					End:   span.Point{Line: line, Column: 1},
				}
				mapping, ok, exact := mappingForGenerated(sourceMap, line, 1)
				applySourceMapping(&diag, mapping, ok, exact)
			}
		}
		if diag.Span.IsZero() && entry.Path != "" && !generatedMatches(entry.Path, sourceMap.Generated.Path) {
			diag.Span = span.Span{
				File:  span.FileID(entry.Path),
				Start: span.Point{Line: entry.Line, Column: entry.Column},
				End:   span.Point{Line: entry.Line, Column: entry.Column + 1},
			}
		}
		diags = append(diags, diag)
	}
	return diags
}

func applySourceMapping(diag *Diagnostic, mapping ir.SourceMapping, ok bool, exact bool) {
	if diag == nil || !ok {
		return
	}
	diag.Span = mapping.Source
	diag.Function = mapping.Function
	diag.Section = mapping.Section
	diag.Node = mapping.Node
	if exact {
		diag.Mapping = "exact"
	} else {
		diag.Mapping = "nearest"
	}
}

func mappingForGenerated(sourceMap ir.SourceMap, line int, column int) (ir.SourceMapping, bool, bool) {
	if line <= 0 {
		return ir.SourceMapping{}, false, false
	}
	best := ir.SourceMapping{}
	bestSet := false
	for _, mapping := range sourceMap.Mappings {
		if !containsGenerated(mapping.Generated, line, column) {
			continue
		}
		if !bestSet || generatedSize(mapping.Generated) < generatedSize(best.Generated) {
			best = mapping
			bestSet = true
		}
	}
	if bestSet {
		return best, true, true
	}
	for _, mapping := range sourceMap.Mappings {
		if mapping.Generated.Start.Line > line {
			continue
		}
		if !bestSet || mapping.Generated.Start.Line > best.Generated.Start.Line {
			best = mapping
			bestSet = true
		}
	}
	if bestSet {
		return best, true, false
	}
	return ir.SourceMapping{}, false, false
}

func containsGenerated(generated span.Span, line int, column int) bool {
	if generated.Start.Line == 0 {
		return false
	}
	if column <= 0 {
		column = 1
	}
	start := generated.Start
	end := generated.End
	if end.Line == 0 {
		end = start
	}
	if line < start.Line || line > end.Line {
		return false
	}
	if line == start.Line && column < start.Column {
		return false
	}
	if line == end.Line && end.Column > 0 && column >= end.Column {
		return false
	}
	return true
}

func generatedSize(generated span.Span) int {
	lines := generated.End.Line - generated.Start.Line
	columns := generated.End.Column - generated.Start.Column
	return lines*10000 + columns
}

func generatedMatches(path string, generatedPath string) bool {
	if path == "" {
		return true
	}
	if generatedPath == "" {
		return true
	}
	cleanPath := filepath.Clean(path)
	cleanGenerated := filepath.Clean(generatedPath)
	return cleanPath == cleanGenerated || filepath.Base(cleanPath) == filepath.Base(cleanGenerated)
}

func generatedLines(generated []byte) []string {
	if len(generated) == 0 {
		return nil
	}
	text := strings.ReplaceAll(string(generated), "\r\n", "\n")
	return strings.Split(text, "\n")
}

func findGeneratedLine(lines []string, source string) int {
	source = normalizeCSource(source)
	if source == "" {
		return 0
	}
	for i, line := range lines {
		if normalizeCSource(line) == source {
			return i + 1
		}
	}
	for i, line := range lines {
		if strings.Contains(normalizeCSource(line), source) {
			return i + 1
		}
	}
	return 0
}

func normalizeCSource(source string) string {
	source = strings.TrimSpace(source)
	source = strings.TrimSuffix(source, ";")
	return strings.Join(strings.Fields(source), " ")
}
