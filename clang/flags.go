package clang

import (
	"path/filepath"
	"runtime"
)

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

// reproducibleFlags removes the caller's output directory from debug and
// preprocessor metadata. Generated artifacts with the same source bytes and
// filename are therefore independent of the directory used for the build.
func reproducibleFlags(input string) []string {
	dir := filepath.Clean(filepath.Dir(input))
	if absolute, err := filepath.Abs(dir); err == nil {
		dir = absolute
	}
	return []string{
		"-fdebug-compilation-dir=.",
		"-fdebug-prefix-map=" + dir + "=.",
		"-ffile-prefix-map=" + dir + "=.",
		"-fmacro-prefix-map=" + dir + "=.",
	}
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
