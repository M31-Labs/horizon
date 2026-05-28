// Package compiler — build matrix.
//
// BuildContext captures the active OS, architecture, kernel version, and BTF
// presence for a Horizon build. Files carrying `//hzn:build <expr>`
// directives (per parser.ExtractBuildTags) are evaluated against the active
// context by BuildContext.Matches; expressions that evaluate to false cause
// the file to be skipped before parsing.
//
// DetectContext probes the process environment for the active context once
// (cached behind a sync.Once for the process lifetime — O-7) and honors the
// per-dimension env-var overrides `HORIZON_BUILD_OS`, `HORIZON_BUILD_ARCH`,
// `HORIZON_BUILD_KERNEL`, `HORIZON_BUILD_BTF`. Tests reset the cache via
// resetContextCache.
//
// The expression grammar is hand-rolled recursive descent:
//
//	expr    := or
//	or      := and ( '||' and )*
//	and     := unary ( '&&' unary )*
//	unary   := '!' unary | primary
//	primary := IDENT | KERNEL_CMP | '(' expr ')'
//	IDENT       := one of the known os/arch/btf tokens
//	KERNEL_CMP  := 'kernel' ( '>=' | '<=' | '==' | '<' | '>' ) MAJOR '.' MINOR
package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// BuildContext is the per-build environment snapshot consulted by the
// `//hzn:build` matcher.
type BuildContext struct {
	OS     string
	Arch   string
	Kernel string // major.minor only, e.g. "5.15"
	BTF    bool
}

// Closed dimension whitelists. Identifiers outside these sets surface as
// "unknown identifier" errors from Matches.
var (
	knownOSes    = map[string]bool{"linux": true, "darwin": true, "windows": true, "freebsd": true}
	knownArches  = map[string]bool{"amd64": true, "arm64": true, "riscv64": true}
	btfDimension = "btf"
)

var (
	cachedContext     BuildContext
	cachedContextOnce sync.Once
)

// resetContextCache clears the sync.Once-backed DetectContext cache.
// Test-only — exported for use by other tests in the compiler package
// (such as imports_test) that need to apply env-var overrides between
// calls.
func resetContextCache() {
	cachedContextOnce = sync.Once{}
	cachedContext = BuildContext{}
}

// DetectContext returns the active build context, cached for the process
// lifetime (O-7). Per-dimension env-var overrides are honored:
//
//   - HORIZON_BUILD_OS     — overrides runtime.GOOS
//   - HORIZON_BUILD_ARCH   — overrides runtime.GOARCH
//   - HORIZON_BUILD_KERNEL — overrides the parsed `uname -r` major.minor
//   - HORIZON_BUILD_BTF    — "1"/"true"/"yes" → true; "0"/"false"/"no" → false
//
// The cache makes repeated calls free; tests reset via resetContextCache.
func DetectContext() BuildContext {
	cachedContextOnce.Do(func() {
		cachedContext = probeContext()
	})
	return cachedContext
}

func probeContext() BuildContext {
	ctx := BuildContext{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	if v := os.Getenv("HORIZON_BUILD_OS"); v != "" {
		ctx.OS = v
	}
	if v := os.Getenv("HORIZON_BUILD_ARCH"); v != "" {
		ctx.Arch = v
	}
	if v := os.Getenv("HORIZON_BUILD_KERNEL"); v != "" {
		ctx.Kernel = v
	} else {
		ctx.Kernel = detectKernel()
	}
	if v := os.Getenv("HORIZON_BUILD_BTF"); v != "" {
		ctx.BTF = parseBoolish(v)
	} else {
		ctx.BTF = detectBTF()
	}
	return ctx
}

// detectKernel shells out to `uname -r` and parses the leading
// major.minor. Returns "" if uname is unavailable or the output does not
// look like a kernel version (callers may then choose to skip kernel
// constraints rather than evaluate against an unknown value).
func detectKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return parseKernelMajorMinor(strings.TrimSpace(string(out)))
}

// parseKernelMajorMinor extracts the leading `<major>.<minor>` from a
// version string like "5.15.0-1023-aws". Trailing patch / vendor suffix
// is ignored.
func parseKernelMajorMinor(s string) string {
	if s == "" {
		return ""
	}
	// Trim anything that isn't a digit or dot at the front.
	end := 0
	dots := 0
	for end < len(s) {
		c := s[end]
		if c >= '0' && c <= '9' {
			end++
			continue
		}
		if c == '.' && dots < 1 {
			dots++
			end++
			continue
		}
		break
	}
	prefix := s[:end]
	parts := strings.SplitN(prefix, ".", 2)
	if len(parts) < 2 {
		return ""
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return ""
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func detectBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

func parseBoolish(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Matches evaluates expr against ctx. Returns (true, nil) when the
// expression is satisfied, (false, nil) when unsatisfied, and a non-nil
// error when the expression itself is malformed (unknown identifier,
// invalid kernel comparison, unbalanced paren, etc.).
func (ctx BuildContext) Matches(expr string) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false, fmt.Errorf("build constraint expression is empty")
	}
	p := &matcherParser{src: expr, ctx: ctx}
	result, err := p.parseOr()
	if err != nil {
		return false, err
	}
	p.skipSpace()
	if p.pos != len(p.src) {
		return false, fmt.Errorf("build constraint expression %q: unexpected trailing input at position %d", expr, p.pos)
	}
	return result, nil
}

// matcherParser is a single-use recursive-descent parser-evaluator. It
// produces a boolean directly rather than building an AST — the grammar
// is small enough that fused parse+eval keeps the implementation lean.
type matcherParser struct {
	src string
	pos int
	ctx BuildContext
}

func (p *matcherParser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func (p *matcherParser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

func (p *matcherParser) acceptLit(lit string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.src[p.pos:], lit) {
		p.pos += len(lit)
		return true
	}
	return false
}

func (p *matcherParser) parseOr() (bool, error) {
	left, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for {
		p.skipSpace()
		if !p.acceptLit("||") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		left = left || right
	}
}

func (p *matcherParser) parseAnd() (bool, error) {
	left, err := p.parseUnary()
	if err != nil {
		return false, err
	}
	for {
		p.skipSpace()
		if !p.acceptLit("&&") {
			return left, nil
		}
		right, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		left = left && right
	}
}

func (p *matcherParser) parseUnary() (bool, error) {
	p.skipSpace()
	if p.acceptLit("!") {
		inner, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		return !inner, nil
	}
	return p.parsePrimary()
}

func (p *matcherParser) parsePrimary() (bool, error) {
	p.skipSpace()
	if p.peek() == '(' {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return false, err
		}
		p.skipSpace()
		if p.peek() != ')' {
			return false, fmt.Errorf("build constraint: unbalanced parenthesis at position %d", p.pos)
		}
		p.pos++
		return inner, nil
	}
	ident := p.readIdent()
	if ident == "" {
		return false, fmt.Errorf("build constraint: expected identifier at position %d", p.pos)
	}
	// Kernel comparisons are the only multi-token primary: identifier
	// "kernel" followed immediately (modulo whitespace) by one of
	// >=, <=, ==, <, > and a MAJOR.MINOR.
	if ident == "kernel" {
		return p.parseKernelCmp()
	}
	return p.evalIdent(ident)
}

// readIdent reads a leading run of [a-zA-Z_][a-zA-Z0-9_]*.
func (p *matcherParser) readIdent() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) {
		c := rune(p.src[p.pos])
		if unicode.IsLetter(c) || c == '_' || (p.pos > start && unicode.IsDigit(c)) {
			p.pos++
			continue
		}
		break
	}
	return p.src[start:p.pos]
}

func (p *matcherParser) evalIdent(ident string) (bool, error) {
	switch {
	case knownOSes[ident]:
		return p.ctx.OS == ident, nil
	case knownArches[ident]:
		return p.ctx.Arch == ident, nil
	case ident == btfDimension:
		return p.ctx.BTF, nil
	}
	return false, fmt.Errorf("build constraint: unknown identifier %q (allowed: os values %v, arch values %v, or `btf`)", ident, sortedKeys(knownOSes), sortedKeys(knownArches))
}

func (p *matcherParser) parseKernelCmp() (bool, error) {
	p.skipSpace()
	// Two-char ops first so `>=` is not split into `>` + `=`.
	var op string
	switch {
	case p.acceptLit(">="):
		op = ">="
	case p.acceptLit("<="):
		op = "<="
	case p.acceptLit("=="):
		op = "=="
	case p.acceptLit(">"):
		op = ">"
	case p.acceptLit("<"):
		op = "<"
	default:
		return false, fmt.Errorf("build constraint: `kernel` must be followed by a comparison operator (>=, <=, ==, <, >) at position %d", p.pos)
	}
	p.skipSpace()
	version := p.readVersionLiteral()
	if version == "" {
		return false, fmt.Errorf("build constraint: expected MAJOR.MINOR after `kernel%s` at position %d", op, p.pos)
	}
	return compareKernelVersions(p.ctx.Kernel, op, version)
}

func (p *matcherParser) readVersionLiteral() string {
	start := p.pos
	dots := 0
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c >= '0' && c <= '9' {
			p.pos++
			continue
		}
		if c == '.' && dots < 1 {
			dots++
			p.pos++
			continue
		}
		break
	}
	return p.src[start:p.pos]
}

func compareKernelVersions(have, op, want string) (bool, error) {
	if have == "" {
		return false, fmt.Errorf("build constraint: active kernel version is unknown; set HORIZON_BUILD_KERNEL=<major>.<minor>")
	}
	hMaj, hMin, err := parseVersionPair(have)
	if err != nil {
		return false, fmt.Errorf("active kernel %q: %w", have, err)
	}
	wMaj, wMin, err := parseVersionPair(want)
	if err != nil {
		return false, fmt.Errorf("constraint kernel %q: %w", want, err)
	}
	cmp := 0
	switch {
	case hMaj < wMaj:
		cmp = -1
	case hMaj > wMaj:
		cmp = +1
	case hMin < wMin:
		cmp = -1
	case hMin > wMin:
		cmp = +1
	}
	switch op {
	case ">=":
		return cmp >= 0, nil
	case "<=":
		return cmp <= 0, nil
	case "==":
		return cmp == 0, nil
	case ">":
		return cmp > 0, nil
	case "<":
		return cmp < 0, nil
	}
	return false, fmt.Errorf("build constraint: internal: unhandled operator %q", op)
}

func parseVersionPair(s string) (int, int, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected MAJOR.MINOR, got %q", s)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("major %q: %w", parts[0], err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("minor %q: %w", parts[1], err)
	}
	return maj, min, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Simple insertion sort — len is small enough that import "sort"
	// vs a hand-rolled loop is a wash.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
