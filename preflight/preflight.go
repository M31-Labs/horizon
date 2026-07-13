// Package preflight reports whether the current Linux kernel can load the
// cgroup-scoped BPF-LSM program sets used by Horizon control-mode policies.
package preflight

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Options struct {
	// Root remaps absolute probe paths for tests and host-mounted proc/sys trees.
	Root          string
	KernelRelease string
}

type Report struct {
	KernelRelease    string   `json:"kernelRelease"`
	KernelAtLeast510 bool     `json:"kernelAtLeast510"`
	BTF              bool     `json:"btf"`
	CgroupV2         bool     `json:"cgroupV2"`
	BPFLSMCompiled   bool     `json:"bpfLsmCompiled"`
	BPFLSMEnabled    bool     `json:"bpfLsmEnabled"`
	EnforcementRung  string   `json:"enforcementRung"`
	Issues           []string `json:"issues,omitempty"`
}

func Check(options Options) Report {
	release := strings.TrimSpace(options.KernelRelease)
	if release == "" {
		release = unameRelease()
	}
	report := Report{KernelRelease: release, KernelAtLeast510: kernelAtLeast(release, 5, 10)}
	report.BTF = regularFile(options.Root, "/sys/kernel/btf/vmlinux")
	report.CgroupV2 = regularFile(options.Root, "/sys/fs/cgroup/cgroup.controllers")
	lsms := read(options.Root, "/sys/kernel/security/lsm")
	report.BPFLSMEnabled = listContains(lsms, "bpf")
	config := readGzip(options.Root, "/proc/config.gz")
	if config == "" {
		config = read(options.Root, "/boot/config-"+release)
	}
	report.BPFLSMCompiled = strings.Contains(config, "CONFIG_BPF_LSM=y") || report.BPFLSMEnabled
	if !report.KernelAtLeast510 {
		report.Issues = append(report.Issues, "kernel 5.10 or newer is required")
	}
	if !report.BTF {
		report.Issues = append(report.Issues, "kernel BTF is unavailable at /sys/kernel/btf/vmlinux")
	}
	if !report.CgroupV2 {
		report.Issues = append(report.Issues, "cgroup v2 is not mounted")
	}
	if !report.BPFLSMCompiled {
		report.Issues = append(report.Issues, "CONFIG_BPF_LSM is not enabled")
	} else if !report.BPFLSMEnabled {
		report.Issues = append(report.Issues, "BPF LSM is compiled but absent from the active LSM list")
	}
	if len(report.Issues) == 0 {
		report.EnforcementRung = "R1-bpf-lsm"
	} else {
		report.EnforcementRung = "R0-lower-walls-only"
	}
	return report
}

func readGzip(root, path string) string {
	file, err := os.Open(probePath(root, path))
	if err != nil {
		return ""
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return ""
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return ""
	}
	return string(data)
}

func (r Report) Ready() bool { return r.EnforcementRung == "R1-bpf-lsm" }

func regularFile(root, path string) bool {
	info, err := os.Stat(probePath(root, path))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func read(root, path string) string {
	data, err := os.ReadFile(probePath(root, path))
	if err != nil {
		return ""
	}
	return string(data)
}

func probePath(root, path string) string {
	if strings.TrimSpace(root) == "" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func listContains(value, wanted string) bool {
	for _, item := range strings.Split(strings.TrimSpace(value), ",") {
		if strings.TrimSpace(item) == wanted {
			return true
		}
	}
	return false
}

func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	actualMajor, errMajor := strconv.Atoi(parts[0])
	actualMinor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return false
	}
	return actualMajor > major || actualMajor == major && actualMinor >= minor
}

func unameRelease() string {
	var value syscall.Utsname
	if err := syscall.Uname(&value); err != nil {
		return "unknown"
	}
	bytes := make([]byte, 0, len(value.Release))
	for _, char := range value.Release {
		if char == 0 {
			break
		}
		bytes = append(bytes, byte(char))
	}
	return string(bytes)
}

func (r Report) String() string {
	return fmt.Sprintf("%s (kernel=%s btf=%t cgroupV2=%t bpfLsm=%t)", r.EnforcementRung, r.KernelRelease, r.BTF, r.CgroupV2, r.BPFLSMEnabled)
}
