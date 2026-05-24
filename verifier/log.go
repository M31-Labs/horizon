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
}

var clangDiagnosticRE = regexp.MustCompile(`^(.+?):([0-9]+):([0-9]+):\s*(fatal error|error|warning|note):\s*(.+)$`)

func ParseLog(raw string) Log {
	log := Log{Raw: raw}
	var lastSource string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if entry, ok := parseClangDiagnostic(trimmed); ok {
			log.Entries = append(log.Entries, entry)
			continue
		}
		if strings.HasPrefix(trimmed, ";") {
			lastSource = strings.TrimSpace(strings.TrimPrefix(trimmed, ";"))
			continue
		}
		if lastSource != "" && looksLikeVerifierDiagnostic(trimmed) {
			log.Entries = append(log.Entries, LogEntry{
				Raw:       trimmed,
				Message:   trimmed,
				Severity:  "error",
				CSource:   lastSource,
				Generated: true,
			})
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
