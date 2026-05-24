package clang

import "runtime"

type Options struct {
	ClangPath string
	Flags     []string
}

func (o Options) ClangPathOrDefault() string {
	if o.ClangPath != "" {
		return o.ClangPath
	}
	return "clang"
}

func DefaultFlags() []string {
	flags := []string{"-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror"}
	if define := TargetArchDefine(runtime.GOARCH); define != "" {
		flags = append(flags, "-D"+define)
	}
	return flags
}

func TargetArchDefine(goarch string) string {
	switch goarch {
	case "386", "amd64":
		return "__TARGET_ARCH_x86"
	case "arm":
		return "__TARGET_ARCH_arm"
	case "arm64":
		return "__TARGET_ARCH_arm64"
	case "mips", "mipsle", "mips64", "mips64le":
		return "__TARGET_ARCH_mips"
	case "ppc64", "ppc64le":
		return "__TARGET_ARCH_powerpc"
	case "riscv64":
		return "__TARGET_ARCH_riscv"
	case "s390x":
		return "__TARGET_ARCH_s390"
	case "loong64":
		return "__TARGET_ARCH_loongarch"
	default:
		return ""
	}
}
