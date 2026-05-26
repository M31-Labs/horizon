package verifier

import (
	"regexp"
	"strconv"
	"strings"
)

type Log struct {
	Raw     string
	Entries []LogEntry
}

type LogEntry struct {
	Raw       string
	Message   string
	Severity  string
	Path      string
	Line      int
	Column    int
	CSource   string
	Generated bool
	// Kind records which producer recognised this entry. Set to
	// "clang_diagnostic" when the line parses as the clang
	// `path:line:col: severity: message` shape, and "verifier" when
	// the line is recognised by looksLikeVerifierDiagnostic against a
	// preceding C-source marker. Empty when neither applies
	// (e.g., synthetic fallback entries built downstream). The diagnose
	// path uses this to gate the verifier-message catalog so verifier
	// remediation does not leak into clang-rooted diagnostics
	// (roadmap #14, plan Task 5.4).
	Kind string
}

var clangDiagnosticRE = regexp.MustCompile(`^(.+?):([0-9]+):([0-9]+):\s*(fatal error|error|warning|note):\s*(.+)$`)

func ParseLog(raw string) Log {
	log := Log{Raw: raw}
	var lastSource string
	var context []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if entry, ok := parseClangDiagnostic(trimmed); ok {
			log.Entries = append(log.Entries, entry)
			context = nil
			continue
		}
		if strings.HasPrefix(trimmed, ";") {
			lastSource = strings.TrimSpace(strings.TrimPrefix(trimmed, ";"))
			context = appendVerifierContext(context, trimmed)
			continue
		}
		if lastSource != "" && looksLikeVerifierDiagnostic(trimmed) {
			log.Entries = append(log.Entries, LogEntry{
				Raw:       verifierRawContext(context, trimmed),
				Message:   trimmed,
				Severity:  "error",
				CSource:   lastSource,
				Generated: true,
				Kind:      "verifier",
			})
			context = nil
			lastSource = ""
			continue
		}
		if !looksLikeVerifierSummary(trimmed) {
			context = appendVerifierContext(context, trimmed)
		}
	}
	return log
}

func parseClangDiagnostic(line string) (LogEntry, bool) {
	match := clangDiagnosticRE.FindStringSubmatch(line)
	if len(match) != 6 {
		return LogEntry{}, false
	}
	lineNo, _ := strconv.Atoi(match[2])
	columnNo, _ := strconv.Atoi(match[3])
	return LogEntry{
		Raw:       line,
		Message:   match[4] + ": " + match[5],
		Severity:  match[4],
		Path:      match[1],
		Line:      lineNo,
		Column:    columnNo,
		Generated: true,
		Kind:      "clang_diagnostic",
	}, true
}

func looksLikeVerifierDiagnostic(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{
		"invalid ",
		"permission denied",
		"unknown func",
		"unreleased reference",
		"unbounded",
		"misaligned",
		"out of bounds",
		"r0 !read_ok",
		"math between",
		"stack depth",
		"cannot access",
		"failed",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func looksLikeVerifierSummary(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "processed ") ||
		strings.HasPrefix(lower, "verification time ") ||
		strings.HasPrefix(lower, "from ") ||
		strings.HasPrefix(lower, "mark_precise:")
}

func appendVerifierContext(context []string, line string) []string {
	const maxVerifierContextLines = 6
	if line == "" {
		return context
	}
	context = append(context, line)
	if len(context) > maxVerifierContextLines {
		context = context[len(context)-maxVerifierContextLines:]
	}
	return context
}

func verifierRawContext(context []string, message string) string {
	if len(context) == 0 {
		return message
	}
	lines := make([]string, 0, len(context)+1)
	lines = append(lines, context...)
	lines = append(lines, message)
	return strings.Join(lines, "\n")
}
