package clang

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCompileIsIndependentOfOutputDirectory(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("clang not available: %v", err)
	}

	root := t.TempDir()
	objects := make([][]byte, 0, 2)
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(dir, "program.bpf.c")
		output := filepath.Join(dir, "program.bpf.o")
		if err := os.WriteFile(input, []byte("int horizon_reproducible_object;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Compile(context.Background(), input, output, Options{}); err != nil {
			t.Skipf("clang BPF target unavailable: %v", err)
		}
		object, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, object)
	}
	if !bytes.Equal(objects[0], objects[1]) {
		t.Fatal("equivalent generated source produced directory-dependent BPF objects")
	}
}

func TestCompileWithRelativePathsIsIndependentOfOutputDirectory(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("clang not available: %v", err)
	}

	root := t.TempDir()
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	command := func(name string) []byte {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(dir, "program.bpf.c")
		output := filepath.Join(dir, "program.bpf.o")
		if err := os.WriteFile(input, []byte("int horizon_relative_reproducible_object;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		relInput, err := filepath.Rel(workingDir, input)
		if err != nil {
			t.Fatal(err)
		}
		relOutput, err := filepath.Rel(workingDir, output)
		if err != nil {
			t.Fatal(err)
		}
		if err := Compile(context.Background(), relInput, relOutput, Options{}); err != nil {
			t.Skipf("clang BPF target unavailable: %v", err)
		}
		object, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		return object
	}

	first := command("first")
	second := command("second")
	if !bytes.Equal(first, second) {
		t.Fatal("equivalent relative generated paths produced directory-dependent BPF objects")
	}
}
