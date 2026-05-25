package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCreatesSafeExecwatchStarter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "execprobe")
	stdout, err := captureStdout(t, func() error {
		return run([]string{"new", dir})
	})
	if err != nil {
		t.Fatalf("run hzn new: %v", err)
	}
	if !strings.Contains(stdout, "created ") || !strings.Contains(stdout, "hzn workbench") {
		t.Fatalf("stdout = %q, want creation and next-step output", stdout)
	}
	sourcePath := filepath.Join(dir, "exec.hzn")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read starter source: %v", err)
	}
	for _, want := range []string{
		`capability ExecObserve danger observe = "kernel.process.exec.observe"`,
		`event := ExecEvents.reserve()`,
		`if event == nil`,
		`ExecEvents.submit(event)`,
	} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("starter source missing %q:\n%s", want, source)
		}
	}
	requireRunQuietly(t, []string{"fmt", dir, "-check"})
	requireRunQuietly(t, []string{"check", dir})
	requireRunQuietly(t, []string{"workbench", dir, "-o", filepath.Join(t.TempDir(), "dist")})
}

func TestNewCreatesSafeXDPDropStarter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "xdpdrop")
	requireRunQuietly(t, []string{"new", dir, "-template", "xdpdrop", "-package", "netprobe"})
	sourcePath := filepath.Join(dir, "xdp.hzn")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read starter source: %v", err)
	}
	for _, want := range []string{
		`package netprobe`,
		`capability XDPDrop danger drop = "kernel.network.xdp.drop"`,
		`@xdp`,
		`switch xdp.ntohs(tcp.dst_port)`,
		`return xdp.Drop`,
	} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("starter source missing %q:\n%s", want, source)
		}
	}
	requireRunQuietly(t, []string{"fmt", dir, "-check"})
	requireRunQuietly(t, []string{"check", dir})
	requireRunQuietly(t, []string{"workbench", dir, "-o", filepath.Join(t.TempDir(), "dist")})
}

func TestNewRefusesOverwriteWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe")
	requireRunQuietly(t, []string{"new", dir})
	_, err := runQuietly(t, []string{"new", dir})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("run hzn new overwrite error = %v, want already exists", err)
	}
	if _, err := runQuietly(t, []string{"new", dir, "-force"}); err != nil {
		t.Fatalf("run hzn new -force: %v", err)
	}
}

func TestNewRejectsInvalidPackageName(t *testing.T) {
	for _, packageName := range []string{"1bad", "func", "xdp", "bad-name"} {
		dir := filepath.Join(t.TempDir(), "probe")
		_, err := runQuietly(t, []string{"new", dir, "-package", packageName})
		if err == nil || !strings.Contains(err.Error(), "invalid package name") {
			t.Fatalf("run hzn new -package %s error = %v, want invalid package name", packageName, err)
		}
	}
}
