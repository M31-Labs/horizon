package clang

import (
	"context"
	"os/exec"
)

func Compile(ctx context.Context, input string, output string, opts Options) error {
	args := append(DefaultFlags(), opts.Flags...)
	args = append(args, "-c", input, "-o", output)
	cmd := exec.CommandContext(ctx, opts.ClangPathOrDefault(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return &Error{Output: string(out), Err: err}
	}
	return nil
}
