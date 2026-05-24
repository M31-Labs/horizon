package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const clangProbeTimeout = 30 * time.Second

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON report")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	report := runDoctorChecks(defaultDoctorConfig())
	if *jsonOut {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
	} else {
		printDoctorReport(report)
	}
	if !report.Ready {
		return fmt.Errorf("eBPF workbench dependencies are not ready")
	}
	return nil
}

type doctorReport struct {
	Schema string        `json:"schema"`
	Ready  bool          `json:"ready"`
	Checks []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Path     string `json:"path,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Suggest  string `json:"suggest,omitempty"`
}

type doctorConfig struct {
	PathEnv         string
	BTFPath         string
	BPFHeaders      []string
	VmlinuxHeaders  []string
	RunCommand      func(context.Context, string, []string, string) error
	AdditionalTools []string
}

func defaultDoctorConfig() doctorConfig {
	return doctorConfig{
		PathEnv:        os.Getenv("PATH"),
		BTFPath:        "/sys/kernel/btf/vmlinux",
		BPFHeaders:     []string{"/usr/include/bpf/bpf_helpers.h", "/usr/local/include/bpf/bpf_helpers.h"},
		VmlinuxHeaders: []string{"vmlinux.h", "/usr/local/include/vmlinux.h", "/usr/include/vmlinux.h"},
		RunCommand:     runDoctorCommand,
		AdditionalTools: []string{
			"bpftool",
			"llvm-objdump",
			"llvm-strip",
		},
	}
}

func runDoctorChecks(cfg doctorConfig) doctorReport {
	report := doctorReport{
		Schema: "m31labs.dev/horizon/doctor/v0",
		Ready:  true,
	}
	clang := checkCommand(cfg, "clang", true, "install clang with BPF target support")
	report.add(clang)
	if clang.Status == "ok" {
		report.add(checkClangBPF(cfg, clang.Path))
	}
	report.add(checkAnyFile("libbpf headers", cfg.BPFHeaders, true, "install libbpf-dev"))
	report.add(checkAnyFile("vmlinux.h", cfg.VmlinuxHeaders, true, "generate one with `bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/local/include/vmlinux.h`"))
	report.add(checkFile("kernel BTF", cfg.BTFPath, false, "enable kernel BTF or provide a vmlinux.h from another build host"))
	for _, tool := range cfg.AdditionalTools {
		report.add(checkCommand(cfg, tool, false, "install llvm and linux-tools packages"))
	}
	return report
}

func (r *doctorReport) add(check doctorCheck) {
	r.Checks = append(r.Checks, check)
	if check.Required && check.Status != "ok" {
		r.Ready = false
	}
}

func checkCommand(cfg doctorConfig, name string, required bool, suggest string) doctorCheck {
	path, ok := lookPathIn(name, cfg.PathEnv)
	if ok {
		return doctorCheck{Name: name, Status: "ok", Required: required, Path: path}
	}
	status := "warning"
	if required {
		status = "error"
	}
	return doctorCheck{Name: name, Status: status, Required: required, Detail: "not found on PATH", Suggest: suggest}
}

func checkClangBPF(cfg doctorConfig, clangPath string) doctorCheck {
	ctx, cancel := context.WithTimeout(context.Background(), clangProbeTimeout)
	defer cancel()
	err := cfg.RunCommand(ctx, clangPath, []string{"-target", "bpf", "-x", "c", "-c", "-o", os.DevNull, "-"}, "int x;\n")
	if err == nil {
		return doctorCheck{Name: "clang bpf target", Status: "ok", Required: true, Detail: "clang can compile eBPF objects"}
	}
	return doctorCheck{
		Name:     "clang bpf target",
		Status:   "error",
		Required: true,
		Detail:   err.Error(),
		Suggest:  "install a clang build with the BPF backend enabled",
	}
}

func checkAnyFile(name string, paths []string, required bool, suggest string) doctorCheck {
	for _, path := range paths {
		if fileReadable(path) {
			return doctorCheck{Name: name, Status: "ok", Required: required, Path: path}
		}
	}
	status := "warning"
	if required {
		status = "error"
	}
	return doctorCheck{Name: name, Status: status, Required: required, Detail: "not found", Suggest: suggest}
}

func checkFile(name string, path string, required bool, suggest string) doctorCheck {
	if fileReadable(path) {
		return doctorCheck{Name: name, Status: "ok", Required: required, Path: path}
	}
	status := "warning"
	if required {
		status = "error"
	}
	return doctorCheck{Name: name, Status: status, Required: required, Detail: "not found", Suggest: suggest}
}

func fileReadable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func lookPathIn(name string, pathEnv string) (string, bool) {
	if strings.ContainsRune(name, os.PathSeparator) {
		if executable(name) {
			return name, true
		}
		return "", false
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if runtime.GOOS == "windows" {
			for _, ext := range []string{"", ".exe", ".bat", ".cmd"} {
				if executable(candidate + ext) {
					return candidate + ext, true
				}
			}
			continue
		}
		if executable(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func executable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
}

func runDoctorCommand(ctx context.Context, path string, args []string, stdin string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text != "" {
			return fmt.Errorf("%w: %s", err, text)
		}
		return err
	}
	return nil
}

func printDoctorReport(report doctorReport) {
	state := "ready"
	if !report.Ready {
		state = "not ready"
	}
	fmt.Printf("eBPF workbench: %s\n", state)
	for _, check := range report.Checks {
		fmt.Printf("[%s] %s", check.Status, check.Name)
		if check.Path != "" {
			fmt.Printf(": %s", check.Path)
		} else if check.Detail != "" {
			fmt.Printf(": %s", check.Detail)
		}
		fmt.Println()
		if check.Suggest != "" && check.Status != "ok" {
			fmt.Printf("  help: %s\n", check.Suggest)
		}
	}
}
