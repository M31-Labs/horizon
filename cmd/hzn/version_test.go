package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionText(t *testing.T) {
	stdout, err := captureStdout(t, func() error {
		return run([]string{"--version"})
	})
	if err != nil {
		t.Fatalf("run version: %v", err)
	}
	for _, want := range []string{
		"hzn ",
		"module: m31labs.dev/horizon",
		"modified: ",
		"go: go",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("version output = %q, missing %q", stdout, want)
		}
	}
}

func TestVersionJSON(t *testing.T) {
	stdout, err := captureStdout(t, func() error {
		return run([]string{"version", "-json"})
	})
	if err != nil {
		t.Fatalf("run version -json: %v", err)
	}
	var info toolInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("unmarshal version JSON: %v\n%s", err, stdout)
	}
	if info.Name != "hzn" {
		t.Fatalf("name = %q, want hzn", info.Name)
	}
	if info.Version == "" {
		t.Fatal("version is empty")
	}
	if info.Module != modulePath {
		t.Fatalf("module = %q, want %q", info.Module, modulePath)
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Fatalf("go_version = %q, want go prefix", info.GoVersion)
	}
}
