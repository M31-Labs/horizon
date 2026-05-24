package emitc

import (
	"errors"
	"fmt"

	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
	"m31labs.dev/horizon/ir"
)

type UnsupportedNodeError struct {
	Node string
	Kind string
	Span span.Span
}

func (e UnsupportedNodeError) Error() string {
	kind := e.Kind
	if kind == "" {
		kind = "<empty>"
	}
	msg := fmt.Sprintf("emit C: unsupported %s kind %q", e.Node, kind)
	if !e.Span.IsZero() {
		msg += fmt.Sprintf(" at %s:%d:%d", e.Span.File, e.Span.Start.Line, e.Span.Start.Column)
	}
	return msg
}

func DiagnosticForError(err error) (diag.Diagnostic, bool) {
	var unsupported UnsupportedNodeError
	if !errors.As(err, &unsupported) {
		return diag.Diagnostic{}, false
	}
	kind := unsupported.Kind
	if kind == "" {
		kind = "<empty>"
	}
	return diag.Diagnostic{
		Code:     "HZN3000",
		Severity: diag.SeverityError,
		Message:  fmt.Sprintf("cannot emit BPF C for unsupported %s kind %q", unsupported.Node, kind),
		Primary:  unsupported.Span,
		Notes: []string{
			"Horizon only emits compiler-known typed IR into BPF C.",
		},
		Suggest: "keep source within Horizon's supported typed DSL subset before code generation",
	}, true
}

func validateEmittable(program ir.Program) error {
	env := newCEnv(program)
	for _, c := range program.Constants {
		if err := validateRequiredExpr(env, &c.Value, "constant "+c.Name, c.Span); err != nil {
			return err
		}
	}
	for _, fn := range program.Functions {
		env := newCEnv(program)
		for _, param := range fn.Params {
			env.setLocal(param.Name, param.Type)
		}
		for _, stmt := range functionStatements(fn) {
			if err := validateEmittableStatement(env, program, stmt); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEmittableStatement(env *cEnv, program ir.Program, stmt ir.Statement) error {
	switch stmt.Kind {
	case "short_var":
		if stmt.Name == "" {
			return unsupportedStatement(stmt, "short_var missing target")
		}
		if mapName, ok := reserveCall(stmt.Value); ok {
			if err := validateReserveCall(env, stmt.Value, mapName); err != nil {
				return err
			}
			env.setLocal(stmt.Name, ptrToMapValue(mapName, env))
			return nil
		}
		if err := validateRequiredExpr(env, stmt.Value, "short variable value", stmt.Span); err != nil {
			return err
		}
		typ, ok := cExprType(stmt.Value, env)
		if !ok {
			return unsupportedExpr(stmt.Value, "untyped short variable value")
		}
		env.setLocal(stmt.Name, typ)
		return nil
	case "assign":
		if err := validateRequiredExpr(env, stmt.Target, "assignment target", stmt.Span); err != nil {
			return err
		}
		if err := validateRequiredExpr(env, stmt.Value, "assignment value", stmt.Span); err != nil {
			return err
		}
		if stmt.Target != nil && stmt.Target.Kind == "ident" {
			typ, ok := cExprType(stmt.Value, env)
			if !ok {
				return unsupportedExpr(stmt.Value, "untyped assignment value")
			}
			env.setLocal(stmt.Target.Name, typ)
		}
		return nil
	case "expr":
		if mapName, op, _, ok := consumeCall(stmt.Expr); ok {
			return validateConsumeCall(env, stmt.Expr, mapName, op)
		}
		return validateRequiredExpr(env, stmt.Expr, "expression statement", stmt.Span)
	case "return":
		return validateRequiredExpr(env, stmt.Value, "return value", stmt.Span)
	case "if":
		if err := validateRequiredExpr(env, stmt.Cond, "if condition", stmt.Span); err != nil {
			return err
		}
		thenEnv := env.child()
		for _, child := range stmt.Then {
			if err := validateEmittableStatement(thenEnv, program, child); err != nil {
				return err
			}
		}
		elseEnv := env.child()
		for _, child := range stmt.Else {
			if err := validateEmittableStatement(elseEnv, program, child); err != nil {
				return err
			}
		}
		return nil
	case "for":
		loopEnv := env.child()
		if err := validateForInit(loopEnv, program, stmt.Init, stmt.Span); err != nil {
			return err
		}
		if stmt.Cond != nil && stmt.Cond.Kind != "" {
			if err := validateRequiredExpr(loopEnv, stmt.Cond, "for condition", stmt.Span); err != nil {
				return err
			}
		}
		if err := validateForPost(loopEnv, stmt.Post, stmt.Span); err != nil {
			return err
		}
		bodyEnv := loopEnv.child()
		for _, child := range stmt.Body {
			if err := validateEmittableStatement(bodyEnv, program, child); err != nil {
				return err
			}
		}
		return nil
	case "inc":
		if stmt.Name == "" || !validIncOp(stmt.Op) {
			return unsupportedStatement(stmt, "inc")
		}
		if env != nil && !env.hasLocal(stmt.Name) {
			return unsupportedExpr(&ir.Expr{Kind: "ident", Name: stmt.Name, Span: stmt.Span}, "unknown identifier "+stmt.Name)
		}
		return nil
	case "raw":
		return unsupportedStatement(stmt, "raw")
	default:
		return unsupportedStatement(stmt, stmt.Kind)
	}
}

func validateForInit(env *cEnv, program ir.Program, stmt *ir.Statement, primary span.Span) error {
	if stmt == nil {
		return nil
	}
	switch stmt.Kind {
	case "short_var", "assign":
		return validateEmittableStatement(env, program, *stmt)
	default:
		return unsupportedStatementWithSpan("for init", stmt.Kind, primary)
	}
}

func validateForPost(env *cEnv, stmt *ir.Statement, primary span.Span) error {
	if stmt == nil {
		return nil
	}
	if stmt.Kind != "inc" || stmt.Name == "" || !validIncOp(stmt.Op) {
		return unsupportedStatementWithSpan("for post", stmt.Kind, primary)
	}
	if env != nil && !env.hasLocal(stmt.Name) {
		return unsupportedExpr(&ir.Expr{Kind: "ident", Name: stmt.Name, Span: stmt.Span}, "unknown identifier "+stmt.Name)
	}
	return nil
}

func validateRequiredExpr(env *cEnv, expr *ir.Expr, context string, primary span.Span) error {
	if expr == nil {
		return UnsupportedNodeError{Node: "expression", Kind: context, Span: primary}
	}
	return validateEmittableExpr(env, expr)
}

func validateEmittableExpr(env *cEnv, expr *ir.Expr) error {
	if expr == nil {
		return nil
	}
	switch expr.Kind {
	case "ident":
		if expr.Name == "" {
			return unsupportedExpr(expr, "ident")
		}
		if env != nil {
			_, hasConst := env.constants[expr.Name]
			if env.hasLocal(expr.Name) || hasConst {
				return nil
			}
		}
		return unsupportedExpr(expr, "unknown identifier "+expr.Name)
	case "int":
		if expr.Value == "" {
			return unsupportedExpr(expr, "int")
		}
		return nil
	case "bool":
		if expr.Value != "true" && expr.Value != "false" {
			return unsupportedExpr(expr, "bool")
		}
		return nil
	case "nil":
		return nil
	case "selector":
		return validateSelectorExpr(env, expr)
	case "unary":
		if !validUnaryOp(expr.Op) {
			return unsupportedExpr(expr, "unary "+expr.Op)
		}
		return validateRequiredExpr(env, expr.Operand, "unary operand", expr.Span)
	case "binary":
		if !validBinaryOp(expr.Op) {
			return unsupportedExpr(expr, "binary "+expr.Op)
		}
		if err := validateRequiredExpr(env, expr.Left, "left operand", expr.Span); err != nil {
			return err
		}
		return validateRequiredExpr(env, expr.Right, "right operand", expr.Span)
	case "call":
		return validateCallExpr(env, expr)
	case "struct_lit":
		if expr.Name == "" {
			return unsupportedExpr(expr, "struct_lit")
		}
		for i := range expr.Fields {
			if expr.Fields[i].Name == "" {
				return UnsupportedNodeError{Node: "struct literal field", Kind: "<empty>", Span: expr.Fields[i].Span}
			}
			if err := validateEmittableExpr(env, &expr.Fields[i].Value); err != nil {
				return err
			}
		}
		return nil
	case "raw", "string", "unknown", "":
		return unsupportedExpr(expr, expr.Kind)
	default:
		return unsupportedExpr(expr, expr.Kind)
	}
}

func validateSelectorExpr(env *cEnv, expr *ir.Expr) error {
	if expr.Operand == nil || expr.Field == "" {
		return unsupportedExpr(expr, "selector")
	}
	if name := qualifiedName(expr); name != "" {
		if _, ok := xdpActionC(name); ok {
			return nil
		}
		if _, ok := tcActionC(name); ok {
			return nil
		}
		if _, ok := cgroupActionC(name); ok {
			return nil
		}
		if _, ok := cgroupConstantC(name); ok {
			return nil
		}
		if _, ok := lsmActionC(name); ok {
			return nil
		}
		if _, ok := xdpConstantC(name); ok {
			return nil
		}
		switch selectorRoot(expr) {
		case "bpf", "xdp", "tc", "cgroup", "lsm", "kprobe", "kretprobe":
			return unsupportedExpr(expr, name)
		}
	}
	if err := validateRequiredExpr(env, expr.Operand, "selector operand", expr.Span); err != nil {
		return err
	}
	if _, ok := selectorExprType(expr, env); !ok {
		return unsupportedExpr(expr, "selector "+expr.Field)
	}
	return nil
}

func validateCallExpr(env *cEnv, expr *ir.Expr) error {
	if expr.Func == nil {
		return unsupportedExpr(expr, "call")
	}
	if isScalarConversionCall(expr) {
		if err := validateArgCount(expr, qualifiedName(expr.Func), 1); err != nil {
			return err
		}
		return validateArgs(env, expr.Args)
	}
	if expr.Func.Kind == "selector" && expr.Func.Operand != nil && expr.Func.Operand.Kind == "ident" {
		root := expr.Func.Operand.Name
		method := expr.Func.Field
		if root == "bpf" {
			if err := validateBPFCall(expr, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
		if root == "xdp" {
			if err := validateXDPCall(expr, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
		if root == "cgroup" {
			if err := validateCgroupCall(expr, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
		if root == "kprobe" {
			if err := validateKprobeCall(expr, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
		if root == "kretprobe" {
			if err := validateKretprobeCall(expr, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
		if m, ok := env.maps[root]; ok {
			if err := validateMapCall(expr, m, method); err != nil {
				return err
			}
			return validateArgs(env, expr.Args)
		}
	}
	return unsupportedExpr(expr, "call "+qualifiedName(expr.Func))
}

func validateBPFCall(expr *ir.Expr, method string) error {
	switch method {
	case "current_pid", "current_ppid", "current_uid", "ktime_get_ns":
		return validateArgCount(expr, "bpf."+method, 0)
	case "current_comm":
		return validateArgCount(expr, "bpf.current_comm", 1)
	default:
		return unsupportedExpr(expr, "bpf."+method)
	}
}

func validateXDPCall(expr *ir.Expr, method string) error {
	switch method {
	case "eth", "ipv4", "tcp", "udp", "ntohs":
		return validateArgCount(expr, "xdp."+method, 1)
	default:
		return unsupportedExpr(expr, "xdp."+method)
	}
}

func validateCgroupCall(expr *ir.Expr, method string) error {
	switch method {
	case "family", "sock_type", "protocol", "dst_port", "dst_ip4", "src_ip4":
		return validateArgCount(expr, "cgroup."+method, 1)
	case "ip4":
		return validateArgCount(expr, "cgroup.ip4", 4)
	default:
		return unsupportedExpr(expr, "cgroup."+method)
	}
}

func validateKprobeCall(expr *ir.Expr, method string) error {
	switch method {
	case "arg1", "arg2", "arg3", "arg4", "arg5":
		return validateArgCount(expr, "kprobe."+method, 1)
	default:
		return unsupportedExpr(expr, "kprobe."+method)
	}
}

func validateKretprobeCall(expr *ir.Expr, method string) error {
	switch method {
	case "ret":
		return validateArgCount(expr, "kretprobe.ret", 1)
	default:
		return unsupportedExpr(expr, "kretprobe."+method)
	}
}

func validateMapCall(expr *ir.Expr, m ir.Map, method string) error {
	switch method {
	case "lookup":
		if !m.Kind.IsLookup() {
			return unsupportedExpr(expr, string(m.Kind)+"."+method)
		}
		return validateArgCount(expr, m.Name+"."+method, 1)
	case "update":
		if !m.Kind.IsLookup() {
			return unsupportedExpr(expr, string(m.Kind)+"."+method)
		}
		return validateArgCount(expr, m.Name+"."+method, 2)
	case "delete":
		if !m.Kind.IsHashLike() {
			return unsupportedExpr(expr, string(m.Kind)+"."+method)
		}
		return validateArgCount(expr, m.Name+"."+method, 1)
	case "reserve":
		return unsupportedExpr(expr, m.Name+".reserve")
	case "submit", "discard":
		return unsupportedExpr(expr, m.Name+"."+method)
	default:
		return unsupportedExpr(expr, m.Name+"."+method)
	}
}

func validateReserveCall(env *cEnv, expr *ir.Expr, mapName string) error {
	m, ok := env.maps[mapName]
	if !ok || m.Kind != ir.MapKindRingbuf {
		return unsupportedExpr(expr, mapName+".reserve")
	}
	return validateArgCount(expr, mapName+".reserve", 0)
}

func validateConsumeCall(env *cEnv, expr *ir.Expr, mapName string, op string) error {
	m, ok := env.maps[mapName]
	if !ok || m.Kind != ir.MapKindRingbuf {
		return unsupportedExpr(expr, mapName+"."+op)
	}
	if err := validateArgCount(expr, mapName+"."+op, 1); err != nil {
		return err
	}
	if len(expr.Args) != 1 || expr.Args[0].Kind != "ident" {
		return unsupportedExpr(expr, mapName+"."+op)
	}
	return nil
}

func validateArgCount(expr *ir.Expr, name string, want int) error {
	if len(expr.Args) == want {
		return nil
	}
	return UnsupportedNodeError{Node: "call", Kind: fmt.Sprintf("%s arity %d", name, len(expr.Args)), Span: expr.Span}
}

func validateArgs(env *cEnv, args []ir.Expr) error {
	for i := range args {
		if err := validateEmittableExpr(env, &args[i]); err != nil {
			return err
		}
	}
	return nil
}

func selectorRoot(expr *ir.Expr) string {
	if expr == nil {
		return ""
	}
	switch expr.Kind {
	case "ident":
		return expr.Name
	case "selector":
		return selectorRoot(expr.Operand)
	default:
		return ""
	}
}

func validUnaryOp(op string) bool {
	switch op {
	case "&", "!", "-", "+", "^":
		return true
	default:
		return false
	}
}

func validBinaryOp(op string) bool {
	switch op {
	case "==", "!=", "<", "<=", ">", ">=", "&&", "||",
		"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>":
		return true
	default:
		return false
	}
}

func validIncOp(op string) bool {
	return op == "++" || op == "--"
}

func unsupportedStatement(stmt ir.Statement, kind string) error {
	return UnsupportedNodeError{Node: "statement", Kind: kind, Span: stmt.Span}
}

func unsupportedStatementWithSpan(node string, kind string, sp span.Span) error {
	return UnsupportedNodeError{Node: node, Kind: kind, Span: sp}
}

func unsupportedExpr(expr *ir.Expr, kind string) error {
	sp := span.Span{}
	if expr != nil {
		sp = expr.Span
	}
	return UnsupportedNodeError{Node: "expression", Kind: kind, Span: sp}
}
