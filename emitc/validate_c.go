package emitc

import (
	"fmt"
	"strings"
)

type CValidationError struct {
	Rule    string
	Line    int
	Message string
}

func (e CValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("validate generated C: %s at line %d", e.Message, e.Line)
	}
	return "validate generated C: " + e.Message
}

func ValidateC(source string) error {
	if strings.TrimSpace(source) == "" {
		return CValidationError{Rule: "non_empty", Message: "generated C is empty"}
	}
	for _, required := range []struct {
		rule    string
		snippet string
		message string
	}{
		{rule: "vmlinux_include", snippet: `#include "vmlinux.h"`, message: `missing #include "vmlinux.h"`},
		{rule: "bpf_helpers_include", snippet: `#include <bpf/bpf_helpers.h>`, message: "missing libbpf helper include"},
		{rule: "license_section", snippet: `char LICENSE[] SEC("license") = "GPL";`, message: "missing GPL license section"},
		{rule: "scalar_abi_assertions", snippet: `_Static_assert(sizeof(__u64) == 8`, message: "missing scalar ABI assertions"},
	} {
		if !strings.Contains(source, required.snippet) {
			return CValidationError{Rule: required.rule, Message: required.message}
		}
	}
	return validateCShape(source)
}

func validateCShape(source string) error {
	lines := strings.Split(source, "\n")
	state := cScanState{}
	for i, line := range lines {
		lineNo := i + 1
		if strings.TrimRight(line, " \t") != line {
			return CValidationError{Rule: "trailing_whitespace", Line: lineNo, Message: "line has trailing whitespace"}
		}
		if strings.Contains(line, `SEC("")`) {
			return CValidationError{Rule: "section_name", Line: lineNo, Message: "generated C has an empty BPF section name"}
		}
		clean, err := state.cleanLine(line, lineNo)
		if err != nil {
			return err
		}
		if err := validateCLine(clean, lineNo, state.inStaticInline()); err != nil {
			return err
		}
		if err := state.updateScope(clean, lineNo); err != nil {
			return err
		}
	}
	if state.inBlockComment {
		return CValidationError{Rule: "unterminated_comment", Line: state.blockCommentLine, Message: "unterminated block comment"}
	}
	if state.braceDepth != 0 {
		return CValidationError{Rule: "balanced_braces", Message: "unbalanced braces in generated C"}
	}
	if state.parenDepth != 0 {
		return CValidationError{Rule: "balanced_parentheses", Message: "unbalanced parentheses in generated C"}
	}
	if state.bracketDepth != 0 {
		return CValidationError{Rule: "balanced_brackets", Message: "unbalanced brackets in generated C"}
	}
	return nil
}

func validateCLine(clean string, lineNo int, inStaticInline bool) error {
	trimmed := strings.TrimSpace(clean)
	if trimmed == "" {
		return nil
	}
	for _, banned := range []struct {
		rule    string
		token   string
		message string
	}{
		{rule: "no_malloc", token: "malloc(", message: "generated eBPF C must not allocate heap memory"},
		{rule: "no_calloc", token: "calloc(", message: "generated eBPF C must not allocate heap memory"},
		{rule: "no_realloc", token: "realloc(", message: "generated eBPF C must not allocate heap memory"},
		{rule: "no_free", token: "free(", message: "generated eBPF C must not free heap memory"},
		{rule: "no_printf", token: "printf(", message: "generated eBPF C must not call libc I/O"},
		{rule: "no_fprintf", token: "fprintf(", message: "generated eBPF C must not call libc I/O"},
		{rule: "no_puts", token: "puts(", message: "generated eBPF C must not call libc I/O"},
		{rule: "no_goto", token: "goto ", message: "generated eBPF C must not use goto"},
		{rule: "no_inline_asm", token: "asm(", message: "generated eBPF C must not use inline assembly"},
		{rule: "no_unused_attribute", token: "__attribute__((unused))", message: "generated C must not hide unused code with attributes"},
	} {
		if strings.Contains(trimmed, banned.token) {
			return CValidationError{Rule: banned.rule, Line: lineNo, Message: banned.message}
		}
	}
	if helper, ok := firstDisallowedDirectBPFCall(trimmed); ok && !inStaticInline && !startsStaticInlineFunction(trimmed) {
		return CValidationError{
			Rule:    "helper_wrappers",
			Line:    lineNo,
			Message: fmt.Sprintf("direct %s helper call appears outside a typed Horizon wrapper", helper),
		}
	}
	return nil
}

func firstDisallowedDirectBPFCall(line string) (string, bool) {
	for {
		idx := strings.Index(line, "bpf_")
		if idx < 0 {
			return "", false
		}
		if idx > 0 {
			prev := line[idx-1]
			if isCIdentByte(prev) {
				line = line[idx+4:]
				continue
			}
		}
		rest := line[idx:]
		nameEnd := 4
		for nameEnd < len(rest) && isCIdentByte(rest[nameEnd]) {
			nameEnd++
		}
		after := strings.TrimLeft(rest[nameEnd:], " \t")
		if strings.HasPrefix(after, "(") {
			name := rest[:nameEnd]
			if !allowedDirectBPFMacro(name) {
				return name, true
			}
		}
		line = rest[nameEnd:]
	}
}

func allowedDirectBPFMacro(name string) bool {
	switch name {
	case "bpf_htons", "bpf_htonl", "bpf_ntohs", "bpf_ntohl":
		return true
	default:
		return false
	}
}

func isCIdentByte(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
}

type cScanState struct {
	inBlockComment   bool
	blockCommentLine int
	braceDepth       int
	parenDepth       int
	bracketDepth     int
	staticBaseDepth  int
	staticActive     bool
}

func (s *cScanState) inStaticInline() bool {
	return s.staticActive
}

func (s *cScanState) cleanLine(line string, lineNo int) (string, error) {
	var out strings.Builder
	inString := false
	inRune := false
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		next := byte(0)
		if i+1 < len(line) {
			next = line[i+1]
		}
		if s.inBlockComment {
			if ch == '*' && next == '/' {
				s.inBlockComment = false
				out.WriteString("  ")
				i++
			} else {
				out.WriteByte(' ')
			}
			continue
		}
		if inString {
			out.WriteByte(' ')
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if inRune {
			out.WriteByte(' ')
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '\'' {
				inRune = false
			}
			continue
		}
		if ch == '/' && next == '/' {
			out.WriteString(strings.Repeat(" ", len(line)-i))
			break
		}
		if ch == '/' && next == '*' {
			s.inBlockComment = true
			s.blockCommentLine = lineNo
			out.WriteString("  ")
			i++
			continue
		}
		if ch == '"' {
			inString = true
			out.WriteByte(' ')
			continue
		}
		if ch == '\'' {
			inRune = true
			out.WriteByte(' ')
			continue
		}
		out.WriteByte(ch)
	}
	if inString {
		return "", CValidationError{Rule: "unterminated_string", Line: lineNo, Message: "unterminated string literal"}
	}
	if inRune {
		return "", CValidationError{Rule: "unterminated_rune", Line: lineNo, Message: "unterminated character literal"}
	}
	return out.String(), nil
}

func (s *cScanState) updateScope(clean string, lineNo int) error {
	enterStatic := startsStaticInlineFunction(strings.TrimSpace(clean))
	if enterStatic {
		s.staticActive = true
		s.staticBaseDepth = s.braceDepth
	}
	for i := 0; i < len(clean); i++ {
		switch clean[i] {
		case '{':
			s.braceDepth++
		case '}':
			s.braceDepth--
			if s.braceDepth < 0 {
				return CValidationError{Rule: "balanced_braces", Line: lineNo, Message: "closing brace without matching opening brace"}
			}
		case '(':
			s.parenDepth++
		case ')':
			s.parenDepth--
			if s.parenDepth < 0 {
				return CValidationError{Rule: "balanced_parentheses", Line: lineNo, Message: "closing parenthesis without matching opening parenthesis"}
			}
		case '[':
			s.bracketDepth++
		case ']':
			s.bracketDepth--
			if s.bracketDepth < 0 {
				return CValidationError{Rule: "balanced_brackets", Line: lineNo, Message: "closing bracket without matching opening bracket"}
			}
		}
	}
	if s.staticActive && s.braceDepth <= s.staticBaseDepth {
		s.staticActive = false
	}
	return nil
}

func startsStaticInlineFunction(line string) bool {
	return strings.HasPrefix(line, "static __always_inline ") && strings.Contains(line, "{")
}
