package execx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath(file string) (string, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%s %v failed: %w: %s", name, args, err, stderr.String())
		}
		return nil, fmt.Errorf("%s %v failed: %w", name, args, err)
	}
	return stdout.Bytes(), nil
}

func (OSRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}
