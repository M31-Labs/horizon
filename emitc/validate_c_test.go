package emitc

import (
	"errors"
	"strings"
	"testing"

	"m31labs.dev/horizon/compiler"
)

func TestValidateGeneratedCFromExamples(t *testing.T) {
	for _, path := range []string{
		"../examples/execwatch",
		"../examples/openwatch",
		"../examples/xdpdrop",
	} {
		t.Run(path, func(t *testing.T) {
			result, err := compiler.AnalyzePath(path)
			if err != nil {
				t.Fatalf("AnalyzePath: %v", err)
			}
			out, err := Emit(result.Program)
			if err != nil {
				t.Fatalf("Emit: %v", err)
			}
			if err := ValidateC(out.Code); err != nil {
				t.Fatalf("ValidateC: %v\n%s", err, out.Code)
			}
		})
	}
}

func TestValidateCRejectsMissingPreamble(t *testing.T) {
	err := ValidateC("int x;\n")
	if err == nil {
		t.Fatalf("ValidateC succeeded for incomplete generated C")
	}
	var validation CValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want CValidationError", err)
	}
	if validation.Rule != "vmlinux_include" {
		t.Fatalf("rule = %q, want vmlinux_include", validation.Rule)
	}
	d, ok := DiagnosticForError(err)
	if !ok {
		t.Fatalf("DiagnosticForError did not recognize C validation error")
	}
	if d.Code != "HZN3001" {
		t.Fatalf("diagnostic code = %q, want HZN3001", d.Code)
	}
}

func TestValidateCRejectsDirectBPFHelperOutsideWrapper(t *testing.T) {
	source := strings.Replace(validGeneratedCForValidation(), "hzn_pid();", "bpf_get_current_pid_tgid();", 1)
	err := ValidateC(source)
	if err == nil {
		t.Fatalf("ValidateC succeeded for direct bpf helper call")
	}
	var validation CValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want CValidationError", err)
	}
	if validation.Rule != "helper_wrappers" {
		t.Fatalf("rule = %q, want helper_wrappers", validation.Rule)
	}
}

func TestValidateCAllowsBPFHelperInsideTypedWrapper(t *testing.T) {
	if err := ValidateC(validGeneratedCForValidation()); err != nil {
		t.Fatalf("ValidateC: %v", err)
	}
}

func TestValidateCRejectsDirectBPFHelperInsideUserHelper(t *testing.T) {
	source := strings.Replace(validGeneratedCForValidation(), "hzn_pid", "hzn_fn_pid", 2)
	err := ValidateC(source)
	if err == nil {
		t.Fatalf("ValidateC succeeded for direct bpf helper call inside user helper")
	}
	var validation CValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want CValidationError", err)
	}
	if validation.Rule != "helper_wrappers" {
		t.Fatalf("rule = %q, want helper_wrappers", validation.Rule)
	}
}

func TestValidateCAllowsBPFHelperInsideTypedMapWrapper(t *testing.T) {
	source := strings.Replace(validGeneratedCForValidation(),
		`static __always_inline __u64 hzn_pid(void) {
    return bpf_get_current_pid_tgid();
}`,
		`static __always_inline __u64 *Counts_lookup(__u32 key) {
    return bpf_map_lookup_elem(&Counts, &key);
}`, 1)
	source = strings.Replace(source, "hzn_pid();", "Counts_lookup(0);", 1)
	if err := ValidateC(source); err != nil {
		t.Fatalf("ValidateC: %v", err)
	}
}

func TestValidateCRejectsUnbalancedGeneratedC(t *testing.T) {
	source := strings.TrimSuffix(validGeneratedCForValidation(), "}\n")
	err := ValidateC(source)
	if err == nil {
		t.Fatalf("ValidateC succeeded for unbalanced generated C")
	}
	var validation CValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want CValidationError", err)
	}
	if validation.Rule != "balanced_braces" {
		t.Fatalf("rule = %q, want balanced_braces", validation.Rule)
	}
}

func TestValidateCRejectsKernelHostileConstructs(t *testing.T) {
	source := strings.Replace(validGeneratedCForValidation(), "return 0;", "goto done;\ndone:\n    return 0;", 1)
	err := ValidateC(source)
	if err == nil {
		t.Fatalf("ValidateC succeeded for goto")
	}
	var validation CValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T, want CValidationError", err)
	}
	if validation.Rule != "no_goto" {
		t.Fatalf("rule = %q, want no_goto", validation.Rule)
	}
}

func validGeneratedCForValidation() string {
	return `#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

_Static_assert(sizeof(__u64) == 8, "horizon: __u64 width mismatch");

static __always_inline __u64 hzn_pid(void) {
    return bpf_get_current_pid_tgid();
}

SEC("tracepoint/sched/sched_process_exec")
int OnExec(void *ctx) {
    (void)ctx;
    hzn_pid();
    return 0;
}
`
}
