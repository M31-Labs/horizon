package validate

import (
	"fmt"
	"regexp"
	"strings"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/ir"
)

var (
	ringReserveRE  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*([A-Za-z_][A-Za-z0-9_]*)\.reserve\(\)\s*$`)
	ringNilCheckRE = regexp.MustCompile(`\bif\s+(?:([A-Za-z_][A-Za-z0-9_]*)\s*==\s*nil|nil\s*==\s*([A-Za-z_][A-Za-z0-9_]*))\b`)
	ringConsumeRE  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.(submit|discard)\(([A-Za-z_][A-Za-z0-9_]*)\)\s*$`)
	ringWriteRE    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\.[A-Za-z_][A-Za-z0-9_]*\s*=`)
)

type reserveState struct {
	Map   string
	State string
}

func ValidateRingbuf(program ir.Program) []diag.Diagnostic {
	ringMaps := map[string]ir.Map{}
	for _, m := range program.Maps {
		if m.Kind == ir.MapKindRingbuf {
			ringMaps[m.Name] = m
		}
	}
	if len(ringMaps) == 0 {
		return nil
	}

	var diags []diag.Diagnostic
	for _, fn := range program.Functions {
		states := map[string]reserveState{}
		reportedMissingNil := map[string]bool{}
		for _, line := range bodyLines(fn) {
			if match := ringReserveRE.FindStringSubmatch(line); len(match) == 3 {
				varName, mapName := match[1], match[2]
				if _, ok := ringMaps[mapName]; ok {
					states[varName] = reserveState{Map: mapName, State: "maybe_nil"}
				}
				continue
			}
			if match := ringNilCheckRE.FindStringSubmatch(line); len(match) == 3 {
				varName := match[1]
				if varName == "" {
					varName = match[2]
				}
				if state, ok := states[varName]; ok && state.State == "maybe_nil" {
					state.State = "live"
					states[varName] = state
				}
				continue
			}
			if match := ringConsumeRE.FindStringSubmatch(line); len(match) == 4 {
				mapName, op, varName := match[1], match[2], match[3]
				if _, ok := ringMaps[mapName]; !ok {
					continue
				}
				state, ok := states[varName]
				if !ok {
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2101",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("%s consumes unknown ringbuf reservation %q", op, varName),
						Primary:  fn.Span,
					})
					continue
				}
				switch state.State {
				case "maybe_nil":
					if !reportedMissingNil[varName] {
						diags = append(diags, missingNilCheck(fn, varName))
						reportedMissingNil[varName] = true
					}
					state.State = "consumed"
				case "consumed":
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2102",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("ringbuf reservation %q is submitted or discarded more than once", varName),
						Primary:  fn.Span,
					})
				default:
					state.State = "consumed"
				}
				states[varName] = state
				continue
			}
			if match := ringWriteRE.FindStringSubmatch(line); len(match) == 2 {
				varName := match[1]
				state, ok := states[varName]
				if !ok {
					continue
				}
				switch state.State {
				case "maybe_nil":
					if !reportedMissingNil[varName] {
						diags = append(diags, missingNilCheck(fn, varName))
						reportedMissingNil[varName] = true
					}
				case "consumed":
					diags = append(diags, diag.Diagnostic{
						Code:     "HZN2103",
						Severity: diag.SeverityError,
						Message:  fmt.Sprintf("write to ringbuf reservation %q after submit or discard", varName),
						Primary:  fn.Span,
					})
				}
			}
		}
		for varName, state := range states {
			if state.State == "consumed" {
				continue
			}
			diags = append(diags, diag.Diagnostic{
				Code:     "HZN2104",
				Severity: diag.SeverityError,
				Message:  fmt.Sprintf("ringbuf reservation %q may return without submit or discard", varName),
				Primary:  fn.Span,
			})
		}
	}
	return diags
}

func missingNilCheck(fn ir.Function, varName string) diag.Diagnostic {
	return diag.Diagnostic{
		Code:     "HZN2100",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("ringbuf reservation %q must be checked against nil before use", varName),
		Primary:  fn.Span,
		Suggest:  fmt.Sprintf("guard %s with `if %s == nil { return 0 }` before writing or submitting it", varName, varName),
	}
}

func bodyLines(fn ir.Function) []string {
	text := fn.BodyText
	if text == "" {
		for _, block := range fn.Body {
			for _, stmt := range block.Statements {
				text += "\n" + stmt.Text
			}
		}
	}
	text = strings.ReplaceAll(text, "{", "{\n")
	text = strings.ReplaceAll(text, "}", "\n}")
	raw := strings.Split(text, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || line == "{" || line == "}" {
			continue
		}
		lines = append(lines, strings.TrimSuffix(line, ";"))
	}
	return lines
}
