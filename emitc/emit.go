package emitc

import (
	"fmt"
	"strings"

	"m31labs.dev/horizon/ir"
)

func Emit(program ir.Program) (Output, error) {
	var b strings.Builder
	b.WriteString("#include \"vmlinux.h\"\n")
	b.WriteString("#include <bpf/bpf_helpers.h>\n\n")
	b.WriteString("char LICENSE[] SEC(\"license\") = \"GPL\";\n")
	for _, fn := range program.Functions {
		fmt.Fprintf(&b, "\nSEC(%q)\nint %s(void *ctx) {\n    return 0;\n}\n", fn.Section.Name, fn.Name)
	}
	return Output{Code: b.String()}, nil
}
