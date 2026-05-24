package diag

import (
	"strings"

	"m31labs.dev/horizon/compiler/span"
)

func AttachSourceContexts(diags []Diagnostic, sources map[span.FileID][]byte) []Diagnostic {
	if diags == nil {
		return nil
	}
	out := make([]Diagnostic, len(diags))
	copy(out, diags)
	for i := range out {
		if out[i].Source != nil || out[i].Primary.IsZero() {
			continue
		}
		source, ok := sources[out[i].Primary.File]
		if !ok {
			continue
		}
		out[i] = AttachSourceContext(out[i], source)
	}
	return out
}

func AttachSourceContext(d Diagnostic, source []byte) Diagnostic {
	context, ok := SourceContext(d.Primary, source)
	if !ok {
		return d
	}
	d.Source = context
	return d
}

func SourceContext(sp span.Span, source []byte) (*Source, bool) {
	if sp.IsZero() || sp.Start.Line <= 0 {
		return nil, false
	}
	text, ok := sourceLine(source, sp.Start.Line)
	if !ok {
		return nil, false
	}
	start := sp.Start.Column
	if start <= 0 {
		start = 1
	}
	end := sp.End.Column
	if sp.End.Line != sp.Start.Line || end <= start {
		end = start + 1
	}
	return &Source{
		Line:      sp.Start.Line,
		Column:    start,
		EndColumn: end,
		Text:      text,
		Marker:    markerFor(text, start, end),
	}, true
}

func sourceLine(source []byte, line int) (string, bool) {
	if line <= 0 {
		return "", false
	}
	text := strings.ReplaceAll(string(source), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if line > len(lines) {
		return "", false
	}
	return strings.TrimRight(lines[line-1], "\r"), true
}

func markerFor(text string, start int, end int) string {
	if start <= 0 {
		start = 1
	}
	if end <= start {
		end = start + 1
	}
	var b strings.Builder
	column := 1
	for _, r := range text {
		if column >= start {
			break
		}
		if r == '\t' {
			b.WriteRune('\t')
		} else {
			b.WriteByte(' ')
		}
		column++
	}
	for column < start {
		b.WriteByte(' ')
		column++
	}
	b.WriteString(strings.Repeat("^", end-start))
	return b.String()
}
