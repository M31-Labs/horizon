package emitc

import (
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
)

func TestEmitExecwatchUsesTypedCWrappers(t *testing.T) {
	result, err := compiler.AnalyzePath("../examples/execwatch")
	if err != nil {
		t.Fatalf("AnalyzePath: %v", err)
	}
	out, err := Emit(result.Program)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for _, want := range []string{
		"static __always_inline struct ExecEvent *ExecEvents_reserve(void)",
		"struct ExecEvent *event = ExecEvents_reserve();",
		"event->pid = hzn_current_pid();",
		"hzn_current_comm(&event->comm, sizeof(event->comm));",
		"ExecEvents_submit(event);",
	} {
		if !strings.Contains(out.Code, want) {
			t.Fatalf("generated C missing %q:\n%s", want, out.Code)
		}
	}
}
