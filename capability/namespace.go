package capability

import (
	"strings"

	"m31labs.dev/horizon/internal/registry"
)

func KernelCapabilityNamespaceMismatch(name string, kind string, attach string, section string) (string, bool) {
	if name == "" || !strings.HasPrefix(name, "kernel.") {
		return "", false
	}
	want := ExpectedKernelCapabilityPrefix(kind, attach, section)
	if want == "" || strings.HasPrefix(name, want) {
		return want, false
	}
	return want, true
}

// ExpectedKernelCapabilityPrefix returns the required namespace prefix
// (including trailing dot) for a kernel.* capability attached to a program
// of the given kind and attach string. Returns "" if the combination is
// not registered, which leaves the namespace constraint open.
//
// The prefix is determined by a walk of the canonical capability-namespaces
// registry: the first entry whose attach_surface matches kind AND whose
// attach_strings either contains attach or is empty (surface matches any
// attach) is used.
func ExpectedKernelCapabilityPrefix(kind string, attach string, section string) string {
	attach = programAttach(kind, attach, section)
	reg := registry.MustLoad()
	for _, ns := range reg.Namespaces {
		if ns.AttachSurface != kind {
			continue
		}
		if len(ns.AttachStrings) == 0 {
			// Surface matches any attach string (e.g. xdp, sockops, uprobe).
			return ns.Namespace + "."
		}
		for _, s := range ns.AttachStrings {
			if s == attach {
				return ns.Namespace + "."
			}
		}
	}
	return ""
}

func ProgramSectionDescription(kind string, attach string, section string) string {
	if section != "" {
		return section
	}
	if attach != "" {
		return kind + "/" + attach
	}
	return kind
}

func programAttach(kind string, attach string, section string) string {
	if attach != "" {
		return attach
	}
	prefix := kind + "/"
	if strings.HasPrefix(section, prefix) {
		return strings.TrimPrefix(section, prefix)
	}
	return ""
}
