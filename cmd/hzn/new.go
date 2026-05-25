package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

func runNew(args []string) error {
	fs := flag.NewFlagSet("new", flag.ContinueOnError)
	templateName := fs.String("template", "execwatch", "starter template: execwatch or xdpdrop")
	packageName := fs.String("package", "probes", "Horizon package name")
	capabilityName := fs.String("capability", "", "override template capability name")
	force := fs.Bool("force", false, "overwrite an existing starter file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("new requires exactly one target directory")
	}
	if !validPackageName(*packageName) {
		return fmt.Errorf("invalid package name %q", *packageName)
	}
	tmpl, ok := newTemplates[*templateName]
	if !ok {
		return fmt.Errorf("unknown new template %q", *templateName)
	}
	capability := strings.TrimSpace(*capabilityName)
	if capability == "" {
		capability = tmpl.Capability
	}
	if strings.ContainsAny(capability, "\x00\r\n") {
		return fmt.Errorf("invalid capability name %q", capability)
	}
	targetDir := filepath.Clean(fs.Arg(0))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	targetPath := filepath.Join(targetDir, tmpl.File)
	if !*force {
		if _, err := os.Stat(targetPath); err == nil {
			return fmt.Errorf("%s already exists; pass -force to overwrite it", targetPath)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	source := tmpl.Source(*packageName, capability)
	if err := os.WriteFile(targetPath, []byte(source), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "created %s\n", targetPath)
	fmt.Fprintf(os.Stdout, "next: hzn workbench %s -o dist\n", targetDir)
	return nil
}

type newTemplate struct {
	File       string
	Capability string
	Source     func(packageName string, capability string) string
}

var newTemplates = map[string]newTemplate{
	"execwatch": {
		File:       "exec.hzn",
		Capability: "kernel.process.exec.observe",
		Source:     execwatchStarterSource,
	},
	"xdpdrop": {
		File:       "xdp.hzn",
		Capability: "kernel.network.xdp.drop",
		Source:     xdpdropStarterSource,
	},
}

func execwatchStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

import bpf "m31labs.dev/horizon/runtime/kernel"

type ExecEvent struct {
    ts_ns u64
    pid u32
    ppid u32
    uid u32
    comm [16]u8
}

map ExecEvents ringbuf[ExecEvent]

capability ExecObserve danger observe = %s

@capability(ExecObserve)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    event := ExecEvents.reserve()
    if event == nil {
        return 0
    }
    event.ts_ns = bpf.ktime_get_ns()
    event.pid = bpf.current_pid()
    event.ppid = bpf.current_ppid()
    event.uid = bpf.current_uid()
    bpf.current_comm(&event.comm)
    ExecEvents.submit(event)
    return 0
}
`, packageName, strconv.Quote(capability))
}

func xdpdropStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

capability XDPDrop danger drop = %s

@capability(XDPDrop)
@xdp
func DropWeb(ctx xdp.Context) i32 {
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    switch xdp.ntohs(tcp.dst_port) {
        case 80, 443:
            return xdp.Drop
        default:
            return xdp.Pass
    }
}
`, packageName, strconv.Quote(capability))
}

func validPackageName(name string) bool {
	if name == "" {
		return false
	}
	if reservedStarterPackageNames[name] {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r > unicode.MaxASCII || r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r > unicode.MaxASCII || r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

var reservedStarterPackageNames = map[string]bool{
	"package":    true,
	"import":     true,
	"const":      true,
	"enum":       true,
	"capability": true,
	"danger":     true,
	"type":       true,
	"struct":     true,
	"map":        true,
	"func":       true,
	"var":        true,
	"if":         true,
	"switch":     true,
	"case":       true,
	"default":    true,
	"return":     true,
	"bpf":        true,
	"xdp":        true,
	"tc":         true,
	"cgroup":     true,
	"lsm":        true,
	"kprobe":     true,
	"kretprobe":  true,
	"tracepoint": true,
}
