package capability

import (
	"sort"
	"strconv"
	"strings"

	"m31labs.dev/horizon/ir"
)

func requirementsFromIR(program ir.Program) Requirements {
	var reqs requirementBuilder
	for _, fn := range program.Functions {
		reqs.addProgram(string(fn.Section.Kind), programMinKernel(fn.Section.Kind))
		for _, block := range fn.Body {
			for _, stmt := range block.Statements {
				reqs.walkStatement(stmt)
			}
		}
	}
	for _, m := range program.Maps {
		reqs.addMap(string(m.Kind), mapMinKernel(m.Kind))
	}
	return reqs.build()
}

type requirementBuilder struct {
	programs map[string]string
	maps     map[string]string
	helpers  map[string]string
}

func (b *requirementBuilder) addProgram(name string, minKernel string) {
	if name == "" || minKernel == "" {
		return
	}
	if b.programs == nil {
		b.programs = map[string]string{}
	}
	b.programs[name] = maxKernelVersion(b.programs[name], minKernel)
}

func (b *requirementBuilder) addMap(name string, minKernel string) {
	if name == "" || minKernel == "" {
		return
	}
	if b.maps == nil {
		b.maps = map[string]string{}
	}
	b.maps[name] = maxKernelVersion(b.maps[name], minKernel)
}

func (b *requirementBuilder) addHelper(name string, minKernel string) {
	if name == "" || minKernel == "" {
		return
	}
	if b.helpers == nil {
		b.helpers = map[string]string{}
	}
	b.helpers[name] = maxKernelVersion(b.helpers[name], minKernel)
}

func (b *requirementBuilder) build() Requirements {
	reqs := Requirements{
		Programs: featureRequirements(b.programs),
		Maps:     featureRequirements(b.maps),
		Helpers:  featureRequirements(b.helpers),
	}
	reqs.MinKernel = maxRequirementKernel(reqs)
	return reqs
}

func featureRequirements(in map[string]string) []FeatureRequirement {
	if len(in) == 0 {
		return nil
	}
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]FeatureRequirement, 0, len(names))
	for _, name := range names {
		out = append(out, FeatureRequirement{Name: name, MinKernel: in[name]})
	}
	return out
}

func maxRequirementKernel(reqs Requirements) string {
	max := ""
	for _, item := range reqs.Programs {
		max = maxKernelVersion(max, item.MinKernel)
	}
	for _, item := range reqs.Maps {
		max = maxKernelVersion(max, item.MinKernel)
	}
	for _, item := range reqs.Helpers {
		max = maxKernelVersion(max, item.MinKernel)
	}
	return max
}

func (b *requirementBuilder) walkStatement(stmt ir.Statement) {
	b.walkExpr(stmt.Target)
	b.walkExpr(stmt.Value)
	b.walkExpr(stmt.Expr)
	b.walkExpr(stmt.Cond)
	if stmt.Init != nil {
		b.walkStatement(*stmt.Init)
	}
	if stmt.Post != nil {
		b.walkStatement(*stmt.Post)
	}
	for _, child := range stmt.Then {
		b.walkStatement(child)
	}
	for _, child := range stmt.Else {
		b.walkStatement(child)
	}
	for _, child := range stmt.Body {
		b.walkStatement(child)
	}
}

func (b *requirementBuilder) walkExpr(expr *ir.Expr) {
	if expr == nil {
		return
	}
	if expr.Kind == "call" {
		b.observeCall(expr)
	}
	b.walkExpr(expr.Operand)
	b.walkExpr(expr.Left)
	b.walkExpr(expr.Right)
	b.walkExpr(expr.Func)
	for i := range expr.Args {
		b.walkExpr(&expr.Args[i])
	}
	for i := range expr.Fields {
		b.walkExpr(&expr.Fields[i].Value)
	}
}

func (b *requirementBuilder) observeCall(expr *ir.Expr) {
	if name := qualifiedName(expr.Func); name != "" {
		for _, helper := range compilerHelperRequirements(name) {
			b.addHelper(helper, helperMinKernel(helper))
		}
	}
	if _, method, ok := mapMethodCall(expr); ok {
		if helper, ok := mapMethodHelper(method); ok {
			b.addHelper(helper, helperMinKernel(helper))
		}
	}
}

func compilerHelperRequirements(name string) []string {
	switch name {
	case "bpf.current_pid":
		return []string{"bpf_get_current_pid_tgid"}
	case "bpf.current_ppid":
		return []string{"bpf_get_current_task", "bpf_probe_read_kernel"}
	case "bpf.current_uid":
		return []string{"bpf_get_current_uid_gid"}
	case "bpf.current_comm":
		return []string{"bpf_get_current_comm"}
	case "bpf.probe_read_user_str":
		return []string{"bpf_probe_read_user_str"}
	case "bpf.ktime_get_ns":
		return []string{"bpf_ktime_get_ns"}
	default:
		return nil
	}
}

func mapMethodHelper(method string) (string, bool) {
	switch method {
	case "lookup":
		return "bpf_map_lookup_elem", true
	case "update":
		return "bpf_map_update_elem", true
	case "delete":
		return "bpf_map_delete_elem", true
	case "reserve":
		return "bpf_ringbuf_reserve", true
	case "submit":
		return "bpf_ringbuf_submit", true
	case "discard":
		return "bpf_ringbuf_discard", true
	default:
		return "", false
	}
}

func programMinKernel(kind ir.ProgramKind) string {
	switch kind {
	case ir.ProgramKprobe, ir.ProgramKretprobe, ir.ProgramTC:
		return "4.1"
	case ir.ProgramTracepoint:
		return "4.7"
	case ir.ProgramXDP:
		return "4.8"
	case ir.ProgramCgroup:
		return "4.17"
	case ir.ProgramLSM:
		return "5.7"
	default:
		return ""
	}
}

func mapMinKernel(kind ir.MapKind) string {
	switch kind {
	case ir.MapKindHash, ir.MapKindArray:
		return "3.19"
	case ir.MapKindPerCPUHash, ir.MapKindPerCPUArray:
		return "4.6"
	case ir.MapKindLRUHash, ir.MapKindLRUPerCPU:
		return "4.10"
	case ir.MapKindRingbuf:
		return "5.8"
	default:
		return ""
	}
}

func helperMinKernel(name string) string {
	switch name {
	case "bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_map_delete_elem":
		return "3.19"
	case "bpf_get_current_pid_tgid", "bpf_get_current_uid_gid", "bpf_get_current_comm":
		return "4.1"
	case "bpf_get_current_task":
		return "4.8"
	case "bpf_probe_read_kernel":
		return "5.5"
	case "bpf_probe_read_user_str":
		return "5.5"
	case "bpf_ktime_get_ns":
		return "4.1"
	case "bpf_ringbuf_reserve", "bpf_ringbuf_submit", "bpf_ringbuf_discard":
		return "5.8"
	default:
		return ""
	}
}

func qualifiedName(expr *ir.Expr) string {
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "selector":
		prefix := qualifiedName(expr.Operand)
		if prefix == "" {
			return expr.Field
		}
		return prefix + "." + expr.Field
	default:
		return ""
	}
}

func mapMethodCall(expr *ir.Expr) (string, string, bool) {
	if expr == nil || expr.Kind != "call" || expr.Func == nil || expr.Func.Kind != "selector" {
		return "", "", false
	}
	if expr.Func.Operand == nil || expr.Func.Operand.Kind != "ident" {
		return "", "", false
	}
	switch expr.Func.Field {
	case "lookup", "update", "delete", "reserve", "submit", "discard":
		return expr.Func.Operand.Name, expr.Func.Field, true
	default:
		return "", "", false
	}
}

func maxKernelVersion(a string, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if compareKernelVersion(a, b) < 0 {
		return b
	}
	return a
}

func compareKernelVersion(a string, b string) int {
	amaj, amin, aok := parseKernelVersion(a)
	bmaj, bmin, bok := parseKernelVersion(b)
	if !aok || !bok {
		return strings.Compare(a, b)
	}
	if amaj != bmaj {
		if amaj < bmaj {
			return -1
		}
		return 1
	}
	if amin != bmin {
		if amin < bmin {
			return -1
		}
		return 1
	}
	return 0
}

func parseKernelVersion(version string) (int, int, bool) {
	major, minor, ok := strings.Cut(version, ".")
	if !ok || major == "" || minor == "" {
		return 0, 0, false
	}
	majorValue, err := strconv.Atoi(major)
	if err != nil || majorValue < 0 {
		return 0, 0, false
	}
	minorValue, err := strconv.Atoi(minor)
	if err != nil || minorValue < 0 {
		return 0, 0, false
	}
	return majorValue, minorValue, true
}
