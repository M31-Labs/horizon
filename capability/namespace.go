package capability

import "strings"

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

func ExpectedKernelCapabilityPrefix(kind string, attach string, section string) string {
	attach = programAttach(kind, attach, section)
	switch kind {
	case "tracepoint":
		if attach == "sched:sched_process_exec" {
			return "kernel.process.exec."
		}
	case "xdp":
		return "kernel.network.xdp."
	case "tc":
		return "kernel.network.tc."
	case "cgroup":
		if attach == "connect4" || attach == "connect6" {
			return "kernel.network.connect."
		}
	case "lsm":
		switch attach {
		case "file_open":
			return "kernel.file.open."
		case "bprm_check_security":
			return "kernel.process.exec."
		case "task_kill":
			return "kernel.process.kill."
		}
	case "kprobe", "kretprobe":
		switch attach {
		case "do_sys_openat2":
			return "kernel.file.open."
		case "tcp_v4_connect":
			return "kernel.network.tcp.connect."
		}
	case "uprobe", "uretprobe":
		return "kernel.userspace.exec."
	case "fentry", "fexit":
		switch attach {
		case "do_filp_open":
			return "kernel.file.open."
		case "do_execve", "do_execveat":
			return "kernel.process.exec."
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
