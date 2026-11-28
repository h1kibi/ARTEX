//go:build !windows

package tool

import (
	"context"

	gopty "github.com/aymanbagabas/go-pty"
)

// startPTY launches the command attached to a new pseudo-terminal of the given
// size and returns the master side (read output / write input).
func startPTY(spec ptySpec) (*ptyProc, error) {
	shell, flags := shellCmd()
	ctx := spec.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ptmx, err := gopty.New()
	if err != nil {
		return nil, err
	}
	if spec.Cols > 0 && spec.Rows > 0 {
		_ = ptmx.Resize(spec.Cols, spec.Rows)
	}
	cmd := ptmx.CommandContext(ctx, shell, append(flags, spec.Command)...)
	cmd.Dir = ptyWorkDir(spec.WorkDir)
	cmd.Env = withEnv(spec.Env)
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	return &ptyProc{cmd: cmd, ptmx: ptmx}, nil
}

func ptySupported() bool { return !InteractiveShellDisabled() }
