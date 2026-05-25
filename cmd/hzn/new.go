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
	templateName := fs.String("template", "execwatch", "starter template name")
	packageName := fs.String("package", "probes", "Horizon package name")
	capabilityName := fs.String("capability", "", "override template capability name")
	force := fs.Bool("force", false, "overwrite an existing starter file")
	list := fs.Bool("list", false, "list starter templates")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *list {
		printNewTemplates()
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("new requires exactly one target directory")
	}
	if !validPackageName(*packageName) {
		return fmt.Errorf("invalid package name %q", *packageName)
	}
	tmpl, ok := newTemplates[*templateName]
	if !ok {
		return fmt.Errorf("unknown new template %q; available templates: %s", *templateName, strings.Join(newTemplateNames, ", "))
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
	Summary    string
	Source     func(packageName string, capability string) string
}

var newTemplateNames = []string{
	"execwatch",
	"execcount",
	"openwatch",
	"tcpconnect",
	"kretprobe",
	"xdpdrop",
	"tcpass",
	"cgroupconnect",
	"lsmfile",
}

var newTemplates = map[string]newTemplate{
	"execwatch": {
		File:       "exec.hzn",
		Capability: "kernel.process.exec.observe",
		Summary:    "tracepoint ringbuf process exec events",
		Source:     execwatchStarterSource,
	},
	"execcount": {
		File:       "count.hzn",
		Capability: "kernel.process.exec.count",
		Summary:    "tracepoint hash map process exec counter",
		Source:     execcountStarterSource,
	},
	"openwatch": {
		File:       "open.hzn",
		Capability: "kernel.file.open.observe",
		Summary:    "kprobe ringbuf file open events",
		Source:     openwatchStarterSource,
	},
	"tcpconnect": {
		File:       "tcp.hzn",
		Capability: "kernel.network.tcp.connect.observe",
		Summary:    "kprobe ringbuf tcp connect events",
		Source:     tcpconnectStarterSource,
	},
	"kretprobe": {
		File:       "return.hzn",
		Capability: "kernel.file.open.observe",
		Summary:    "kretprobe typed return value observer",
		Source:     kretprobeStarterSource,
	},
	"xdpdrop": {
		File:       "xdp.hzn",
		Capability: "kernel.network.xdp.drop",
		Summary:    "XDP packet drop policy",
		Source:     xdpdropStarterSource,
	},
	"tcpass": {
		File:       "tc.hzn",
		Capability: "kernel.network.tc.observe",
		Summary:    "TC ingress classifier starter",
		Source:     tcpassStarterSource,
	},
	"cgroupconnect": {
		File:       "connect.hzn",
		Capability: "kernel.network.connect.block",
		Summary:    "cgroup connect4 policy starter",
		Source:     cgroupconnectStarterSource,
	},
	"lsmfile": {
		File:       "file.hzn",
		Capability: "kernel.file.open.observe",
		Summary:    "BPF LSM file_open observer",
		Source:     lsmfileStarterSource,
	},
}

func printNewTemplates() {
	for _, name := range newTemplateNames {
		tmpl := newTemplates[name]
		fmt.Fprintf(os.Stdout, "%-14s %s\n", name, tmpl.Summary)
	}
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

func execcountStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

import bpf "m31labs.dev/horizon/runtime/kernel"

const FirstSeen u64 = 1

type Count struct {
    seen u64
}

map ExecCounts hash[u32, Count]

capability ExecCount danger observe = %s

@capability(ExecCount)
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    count := ExecCounts.lookup(pid)
    if count == nil {
        if ExecCounts.update(pid, Count{seen: FirstSeen}) != 0 {
            return 0
        }
        return 0
    }
    count.seen = count.seen + 1
    return 0
}
`, packageName, strconv.Quote(capability))
}

func openwatchStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

import bpf "m31labs.dev/horizon/runtime/kernel"

type OpenEvent struct {
    pid u32
    uid u32
    comm [16]u8
    path [256]u8
}

map OpenEvents ringbuf[OpenEvent]

capability FileOpenObserve danger observe = %s

@capability(FileOpenObserve)
@kprobe("do_sys_openat2")
func OnOpen(ctx kprobe.Context) i32 {
    event := OpenEvents.reserve()
    if event == nil {
        return 0
    }
    event.pid = bpf.current_pid()
    event.uid = bpf.current_uid()
    bpf.current_comm(&event.comm)
    if bpf.probe_read_user_str(&event.path, kprobe.arg2(ctx)) < 0 {
        OpenEvents.discard(event)
        return 0
    }
    OpenEvents.submit(event)
    return 0
}
`, packageName, strconv.Quote(capability))
}

func tcpconnectStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

import bpf "m31labs.dev/horizon/runtime/kernel"

type TCPConnectEvent struct {
    pid u32
    uid u32
    comm [16]u8
}

map TCPConnectEvents ringbuf[TCPConnectEvent]

capability TCPConnectObserve danger observe = %s

@capability(TCPConnectObserve)
@kprobe("tcp_v4_connect")
func OnTCPConnect(ctx kprobe.Context) i32 {
    event := TCPConnectEvents.reserve()
    if event == nil {
        return 0
    }
    event.pid = bpf.current_pid()
    event.uid = bpf.current_uid()
    bpf.current_comm(&event.comm)
    TCPConnectEvents.submit(event)
    return 0
}
`, packageName, strconv.Quote(capability))
}

func kretprobeStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

capability FileOpenObserve danger observe = %s

@capability(FileOpenObserve)
@kretprobe("do_sys_openat2")
func OnOpenReturn(ctx kretprobe.Context) i32 {
    rc := kretprobe.ret(ctx)
    if rc < 0 {
        return 0
    }
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

func tcpassStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

capability TCObserve danger observe = %s

@capability(TCObserve)
@tc("ingress")
func PassIngress(ctx tc.Context) i32 {
    return tc.OK
}
`, packageName, strconv.Quote(capability))
}

func cgroupconnectStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

capability ConnectBlock danger block = %s

@capability(ConnectBlock)
@cgroup("connect4")
func BlockSMTP(ctx cgroup.Connect) i32 {
    if cgroup.family(ctx) != cgroup.FamilyIPv4 {
        return cgroup.Allow
    }
    if cgroup.protocol(ctx) != cgroup.ProtocolTCP {
        return cgroup.Allow
    }
    if cgroup.dst_port(ctx) == 25 && cgroup.dst_ip4(ctx) != cgroup.ip4(127, 0, 0, 1) {
        return cgroup.Deny
    }
    return cgroup.Allow
}
`, packageName, strconv.Quote(capability))
}

func lsmfileStarterSource(packageName string, capability string) string {
	return fmt.Sprintf(`package %s

capability FileOpenObserve danger observe = %s

@capability(FileOpenObserve)
@lsm("file_open")
func ObserveFileOpen(ctx lsm.Context) i32 {
    return lsm.Allow
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
