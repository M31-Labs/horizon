package clang

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
	return []string{"-target", "bpf", "-O2", "-g"}
}
