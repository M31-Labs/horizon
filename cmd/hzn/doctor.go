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
	"sort"
	"strconv"
	"strings"
	"time"

	"m31labs.dev/horizon/capability"
)

const clangProbeTimeout = 30 * time.Second
const clangProbeAttempts = 3
const clangProbeRetryDelay = 250 * time.Millisecond

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON report")
	capabilitiesPath := fs.String("capabilities", "", "capability manifest path for deploy requirement checks")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var manifests []capability.Manifest
	if *capabilitiesPath != "" {
		manifest, err := readDoctorCapabilityManifest(*capabilitiesPath)
		if err != nil {
			return err
		}
		manifests = append(manifests, manifest)
	}
	report := runDoctorChecks(defaultDoctorConfig(), manifests...)
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
	PathEnv              string
	BTFPath              string
	BPFHeaders           []string
	CoreReadHeaders      []string
	VmlinuxHeaders       []string
	RunCommand           func(context.Context, string, []string, string) error
	AdditionalTools      []string
	ClangProbeAttempts   int
	ClangProbeRetryDelay time.Duration
	RuntimeGOOS          string
	KernelRelease        func() (string, error)
	EffectiveUID         func() int
	ProcStatusPath       string
	TracefsPaths         []string
	KprobeEventPaths     []string
	NetdevPath           string
	TCCommand            string
	CgroupControllers    string
	LSMPath              string
}

func defaultDoctorConfig() doctorConfig {
	return doctorConfig{
		PathEnv:    os.Getenv("PATH"),
		BTFPath:    "/sys/kernel/btf/vmlinux",
		BPFHeaders: []string{"/usr/include/bpf/bpf_helpers.h", "/usr/local/include/bpf/bpf_helpers.h"},
		CoreReadHeaders: []string{
			"/usr/include/bpf/bpf_core_read.h",
			"/usr/local/include/bpf/bpf_core_read.h",
		},
		VmlinuxHeaders: []string{"vmlinux.h", "/usr/local/include/vmlinux.h", "/usr/include/vmlinux.h"},
		RunCommand:     runDoctorCommand,
		AdditionalTools: []string{
			"bpftool",
			"llvm-objdump",
			"llvm-strip",
		},
		RuntimeGOOS:       runtime.GOOS,
		KernelRelease:     defaultKernelRelease,
		EffectiveUID:      os.Geteuid,
		ProcStatusPath:    "/proc/self/status",
		TracefsPaths:      []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"},
		KprobeEventPaths:  []string{"/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"},
		NetdevPath:        "/sys/class/net",
		TCCommand:         "tc",
		CgroupControllers: "/sys/fs/cgroup/cgroup.controllers",
		LSMPath:           "/sys/kernel/security/lsm",
	}
}

func runDoctorChecks(cfg doctorConfig, manifests ...capability.Manifest) doctorReport {
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
	report.add(checkAnyFile("libbpf CO-RE headers", cfg.CoreReadHeaders, true, "install libbpf-dev"))
	report.add(checkAnyFile("vmlinux.h", cfg.VmlinuxHeaders, true, "generate one with `bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/local/include/vmlinux.h`"))
	report.add(checkFile("kernel BTF", cfg.BTFPath, false, "enable kernel BTF or provide a vmlinux.h from another build host"))
	for _, tool := range cfg.AdditionalTools {
		report.add(checkCommand(cfg, tool, false, "install llvm and linux-tools packages"))
	}
	for _, manifest := range manifests {
		addCapabilityManifestChecks(&report, cfg, manifest)
	}
	return report
}

func readDoctorCapabilityManifest(path string) (capability.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return capability.Manifest{}, fmt.Errorf("read capability manifest %s: %w", path, err)
	}
	var manifest capability.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return capability.Manifest{}, fmt.Errorf("read capability manifest %s: %w", path, err)
	}
	if err := capability.Validate(manifest); err != nil {
		return capability.Manifest{}, err
	}
	return manifest, nil
}

func addCapabilityManifestChecks(report *doctorReport, cfg doctorConfig, manifest capability.Manifest) {
	reqs := combinedManifestRequirements(manifest)
	if reqs.MinKernel == "" && len(reqs.Permissions) == 0 && len(reqs.Features) == 0 {
		return
	}
	if reqs.MinKernel != "" {
		report.add(checkKernelRequirement(cfg, reqs.MinKernel))
	}
	for _, permission := range reqs.Permissions {
		report.add(checkPermissionRequirement(cfg, permission))
	}
	for _, feature := range reqs.Features {
		report.add(checkHostFeatureRequirement(cfg, feature))
	}
}

func combinedManifestRequirements(manifest capability.Manifest) capability.Requirements {
	var out capability.Requirements
	if manifest.Requirements != nil {
		mergeDoctorRequirements(&out, *manifest.Requirements)
	}
	for _, cap := range manifest.Capabilities {
		if cap.Requirements != nil {
			mergeDoctorRequirements(&out, *cap.Requirements)
		}
	}
	out.Permissions = sortedDoctorSet(out.Permissions)
	out.Features = sortedDoctorSet(out.Features)
	return out
}

func mergeDoctorRequirements(dst *capability.Requirements, src capability.Requirements) {
	dst.MinKernel = maxDoctorKernel(dst.MinKernel, src.MinKernel)
	for _, items := range [][]capability.FeatureRequirement{src.Programs, src.Maps, src.Helpers} {
		for _, item := range items {
			dst.MinKernel = maxDoctorKernel(dst.MinKernel, item.MinKernel)
		}
	}
	dst.Permissions = append(dst.Permissions, src.Permissions...)
	dst.Features = append(dst.Features, src.Features...)
}

func maxDoctorKernel(a string, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if compareKernelRelease(a, b) < 0 {
		return b
	}
	return a
}

func sortedDoctorSet(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, item := range items {
		if item != "" {
			seen[item] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for item := range seen {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
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
	attempts := cfg.ClangProbeAttempts
	if attempts <= 0 {
		attempts = clangProbeAttempts
	}
	delay := cfg.ClangProbeRetryDelay
	if delay <= 0 {
		delay = clangProbeRetryDelay
	}
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), clangProbeTimeout)
		err = cfg.RunCommand(ctx, clangPath, []string{"-target", "bpf", "-x", "c", "-c", "-o", os.DevNull, "-"}, "int x;\n")
		cancel()
		if err == nil {
			return doctorCheck{Name: "clang bpf target", Status: "ok", Required: true, Detail: "clang can compile eBPF objects"}
		}
		if !transientClangProbeError(err) || attempt == attempts {
			break
		}
		time.Sleep(delay)
	}
	return doctorCheck{
		Name:     "clang bpf target",
		Status:   "error",
		Required: true,
		Detail:   err.Error(),
		Suggest:  "install a clang build with the BPF backend enabled",
	}
}

func transientClangProbeError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "signal: killed") || strings.Contains(text, "signal: terminated")
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

func checkKernelRequirement(cfg doctorConfig, minKernel string) doctorCheck {
	check := doctorCheck{Name: "kernel >= " + minKernel, Required: true}
	if cfg.RuntimeGOOS == "" {
		cfg.RuntimeGOOS = runtime.GOOS
	}
	if cfg.RuntimeGOOS != "linux" {
		check.Status = "error"
		check.Detail = "host OS " + cfg.RuntimeGOOS + " cannot load eBPF programs"
		check.Suggest = "run generated eBPF artifacts on a Linux host"
		return check
	}
	if cfg.KernelRelease == nil {
		cfg.KernelRelease = defaultKernelRelease
	}
	release, err := cfg.KernelRelease()
	if err != nil {
		check.Status = "error"
		check.Detail = err.Error()
		check.Suggest = "ensure `uname -r` is available or run on the target Linux host"
		return check
	}
	if compareKernelRelease(release, minKernel) < 0 {
		check.Status = "error"
		check.Detail = fmt.Sprintf("kernel %s is older than required %s", release, minKernel)
		check.Suggest = "deploy to a host with a new enough kernel for the generated program, map, and helper requirements"
		return check
	}
	check.Status = "ok"
	check.Detail = "kernel " + release
	return check
}

func checkPermissionRequirement(cfg doctorConfig, permission string) doctorCheck {
	check := doctorCheck{Name: "permission " + permission, Required: true}
	ok, detail := hostHasPermission(cfg, permission)
	if ok {
		check.Status = "ok"
		check.Detail = detail
		return check
	}
	check.Status = "error"
	check.Detail = detail
	check.Suggest = permissionSuggestion(permission)
	return check
}

func checkHostFeatureRequirement(cfg doctorConfig, feature string) doctorCheck {
	check := doctorCheck{Name: "host feature " + feature, Required: true}
	if cfg.RuntimeGOOS == "" {
		cfg.RuntimeGOOS = runtime.GOOS
	}
	if cfg.RuntimeGOOS != "linux" {
		check.Status = "error"
		check.Detail = "host OS " + cfg.RuntimeGOOS + " cannot expose Linux eBPF attach features"
		check.Suggest = "run deploy checks on the target Linux host"
		return check
	}
	switch feature {
	case "tracefs":
		return checkAnyDirRequirement(check, cfg.TracefsPaths, "mount tracefs at /sys/kernel/tracing")
	case "kprobes":
		return checkAnyFileRequirement(check, cfg.KprobeEventPaths, "enable kprobes and mount tracefs")
	case "netdev_xdp":
		return checkDirRequirement(check, cfg.NetdevPath, "run on a host with network devices that support XDP")
	case "tc_clsact":
		if cfg.TCCommand == "" {
			cfg.TCCommand = "tc"
		}
		path, ok := lookPathIn(cfg.TCCommand, cfg.PathEnv)
		if ok {
			check.Status = "ok"
			check.Path = path
			check.Detail = "tc command is available for clsact setup"
			return check
		}
		check.Status = "error"
		check.Detail = cfg.TCCommand + " not found on PATH"
		check.Suggest = "install iproute2 or use a loader that configures clsact through netlink"
		return check
	case "cgroup_v2":
		return checkFileRequirement(check, cfg.CgroupControllers, "mount cgroup v2")
	case "bpf_lsm":
		return checkLSMRequirement(check, cfg.LSMPath)
	default:
		check.Status = "error"
		check.Detail = "unknown host feature requirement"
		check.Suggest = "regenerate the capability manifest with this version of Horizon"
		return check
	}
}

func fileReadable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirReadable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func checkAnyDirRequirement(check doctorCheck, paths []string, suggest string) doctorCheck {
	for _, path := range paths {
		if dirReadable(path) {
			check.Status = "ok"
			check.Path = path
			return check
		}
	}
	check.Status = "error"
	check.Detail = "not found"
	check.Suggest = suggest
	return check
}

func checkAnyFileRequirement(check doctorCheck, paths []string, suggest string) doctorCheck {
	for _, path := range paths {
		if fileReadable(path) {
			check.Status = "ok"
			check.Path = path
			return check
		}
	}
	check.Status = "error"
	check.Detail = "not found"
	check.Suggest = suggest
	return check
}

func checkDirRequirement(check doctorCheck, path string, suggest string) doctorCheck {
	if dirReadable(path) {
		check.Status = "ok"
		check.Path = path
		return check
	}
	check.Status = "error"
	check.Detail = "not found"
	check.Suggest = suggest
	return check
}

func checkFileRequirement(check doctorCheck, path string, suggest string) doctorCheck {
	if fileReadable(path) {
		check.Status = "ok"
		check.Path = path
		return check
	}
	check.Status = "error"
	check.Detail = "not found"
	check.Suggest = suggest
	return check
}

func checkLSMRequirement(check doctorCheck, path string) doctorCheck {
	data, err := os.ReadFile(path)
	if err != nil {
		check.Status = "error"
		check.Detail = "not found"
		check.Suggest = "enable BPF LSM and expose /sys/kernel/security/lsm"
		return check
	}
	if !strings.Contains(","+strings.TrimSpace(string(data))+",", ",bpf,") {
		check.Status = "error"
		check.Path = path
		check.Detail = "bpf is not listed in active LSMs"
		check.Suggest = "boot with BPF LSM enabled on the target host"
		return check
	}
	check.Status = "ok"
	check.Path = path
	return check
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
		if ctx.Err() != nil {
			return ctx.Err()
		}
		text := strings.TrimSpace(string(out))
		if text != "" {
			return fmt.Errorf("%w: %s", err, text)
		}
		return err
	}
	return nil
}

func defaultKernelRelease() (string, error) {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func compareKernelRelease(release string, minKernel string) int {
	rmaj, rmin, rok := parseKernelMajorMinor(release)
	mmaj, mmin, mok := parseKernelMajorMinor(minKernel)
	if !rok || !mok {
		return strings.Compare(release, minKernel)
	}
	if rmaj != mmaj {
		if rmaj < mmaj {
			return -1
		}
		return 1
	}
	if rmin != mmin {
		if rmin < mmin {
			return -1
		}
		return 1
	}
	return 0
}

func parseKernelMajorMinor(version string) (int, int, bool) {
	version = strings.TrimSpace(version)
	majorText, rest, ok := strings.Cut(version, ".")
	if !ok || majorText == "" {
		return 0, 0, false
	}
	minorEnd := 0
	for minorEnd < len(rest) && rest[minorEnd] >= '0' && rest[minorEnd] <= '9' {
		minorEnd++
	}
	if minorEnd == 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 0 {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(rest[:minorEnd])
	if err != nil || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

const (
	linuxCapNetAdmin = 12
	linuxCapSysAdmin = 21
	linuxCapPerfmon  = 38
	linuxCapBPF      = 39
)

func hostHasPermission(cfg doctorConfig, permission string) (bool, string) {
	if cfg.RuntimeGOOS == "" {
		cfg.RuntimeGOOS = runtime.GOOS
	}
	if cfg.RuntimeGOOS != "linux" {
		return false, "host OS " + cfg.RuntimeGOOS + " cannot hold Linux eBPF permissions"
	}
	switch permission {
	case "bpf_program_load":
		return hostHasAnyCapability(cfg, "CAP_BPF or CAP_SYS_ADMIN", linuxCapBPF, linuxCapSysAdmin)
	case "perf_event_open":
		return hostHasAnyCapability(cfg, "CAP_PERFMON or CAP_SYS_ADMIN", linuxCapPerfmon, linuxCapSysAdmin)
	case "net_admin":
		return hostHasAnyCapability(cfg, "CAP_NET_ADMIN", linuxCapNetAdmin)
	case "cgroup_admin", "lsm_admin":
		return hostHasAnyCapability(cfg, "CAP_SYS_ADMIN", linuxCapSysAdmin)
	default:
		return false, "unknown permission requirement"
	}
}

func hostHasAnyCapability(cfg doctorConfig, label string, caps ...int) (bool, string) {
	mask, ok, err := linuxEffectiveCapabilityMask(cfg)
	if ok {
		for _, capID := range caps {
			if mask&(uint64(1)<<capID) != 0 {
				return true, "effective capabilities include " + label
			}
		}
		return false, "effective capabilities do not include " + label
	}
	if cfg.EffectiveUID == nil {
		cfg.EffectiveUID = os.Geteuid
	}
	if cfg.EffectiveUID() == 0 {
		return true, "effective uid is 0; capability mask unavailable"
	}
	if err != nil {
		return false, "effective capability mask unavailable: " + err.Error()
	}
	return false, "effective capabilities do not include " + label
}

func linuxEffectiveCapabilityMask(cfg doctorConfig) (uint64, bool, error) {
	if cfg.ProcStatusPath == "" {
		cfg.ProcStatusPath = "/proc/self/status"
	}
	data, err := os.ReadFile(cfg.ProcStatusPath)
	if err != nil {
		return 0, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "CapEff" {
			continue
		}
		text := strings.TrimSpace(value)
		mask, err := strconv.ParseUint(text, 16, 64)
		if err != nil {
			return 0, false, err
		}
		return mask, true, nil
	}
	return 0, false, fmt.Errorf("CapEff not found in %s", cfg.ProcStatusPath)
}

func permissionSuggestion(permission string) string {
	switch permission {
	case "bpf_program_load":
		return "run with CAP_BPF or CAP_SYS_ADMIN, or use a privileged loader service"
	case "perf_event_open":
		return "run with CAP_PERFMON or CAP_SYS_ADMIN for tracing attaches"
	case "net_admin":
		return "run with CAP_NET_ADMIN for XDP or tc attachment"
	case "cgroup_admin":
		return "run with CAP_SYS_ADMIN or a cgroup-aware privileged loader"
	case "lsm_admin":
		return "run with CAP_SYS_ADMIN on a host with BPF LSM enabled"
	default:
		return "regenerate the capability manifest with this version of Horizon"
	}
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
