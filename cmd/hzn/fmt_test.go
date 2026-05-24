package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFmtCheckReportsUnformattedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.hzn")
	if err := os.WriteFile(path, []byte(`package probes
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec)i32{return 0}
`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, err := runQuietly(t, []string{"fmt", dir, "-check"})
	if err == nil || !strings.Contains(err.Error(), "need formatting") {
		t.Fatalf("run fmt -check error = %v, want formatting error", err)
	}
}

func TestFmtWriteFormatsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.hzn")
	if err := os.WriteFile(path, []byte(`package probes
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec)i32{return 0}
`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := run([]string{"fmt", path, "-w"}); err != nil {
		t.Fatalf("run fmt -w: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read formatted: %v", err)
	}
	want := `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`
	if string(data) != want {
		t.Fatalf("formatted file mismatch\nwant:\n%s\ngot:\n%s", want, data)
	}
	if err := run([]string{"fmt", path, "-check"}); err != nil {
		t.Fatalf("run fmt -check formatted file: %v", err)
	}
}

func TestFmtStdoutSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.hzn")
	if err := os.WriteFile(path, []byte(`package probes
@xdp
func Drop(ctx xdp.Context)i32{return xdp.Pass}
`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, err := captureStdout(t, func() error {
		return run([]string{"fmt", path})
	})
	if err != nil {
		t.Fatalf("run fmt stdout: %v", err)
	}
	if !strings.Contains(stdout, "func Drop(ctx xdp.Context) i32 {") || !strings.Contains(stdout, "return xdp.Pass") {
		t.Fatalf("stdout did not contain formatted source:\n%s", stdout)
	}
}
