//go:build windows

package tool

import (
	"context"

	gopty "github.com/aymanbagabas/go-pty"
)

// startPTY launches the command inside a real Windows pseudo-console.
//
// Two backends share the same ConPTY: when WSL is available (named by the tool
// env, else the machine default) the console hosts `wsl.exe`, which forwards the
// terminal — with its window size — to the Linux side, so bash gets a native PTY
// without util-linux script(1). When WSL is explicitly disabled, or the machine
// has no user distro, the console hosts the local Windows shell instead.
func startPTY(spec ptySpec) (*ptyProc, error) {
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

	if !wslDistroDisabledInEnv(spec.Env) {
		distro := wslDistroFromEnv(spec.Env)
		if distro == "" {
			distro = defaultWSLDistro()
		}
		if distro != "" {
			cmd := wslPTYCmd(ctx, ptmx, distro, spec)
			if err := cmd.Start(); err != nil {
				_ = ptmx.Close()
				return nil, err
			}
			ensureWSLKeepalive(distro)
			return &ptyProc{cmd: cmd, ptmx: ptmx}, nil
		}
	}

	cmd := ptmx.CommandContext(ctx, windowsPowerShellExe(),
		"-NoLogo", "-NoProfile", "-Command", wrapLocalShellCommand(spec.Command))
	cmd.Dir = ptyWorkDir(spec.WorkDir)
	cmd.Env = withEnv(spec.Env)
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	return &ptyProc{cmd: cmd, ptmx: ptmx}, nil
}

// wslPTYCmd builds the wsl.exe invocation hosted by the ConPTY. The terminal is
// the Windows console itself, so no in-guest terminal emulator is needed.
func wslPTYCmd(ctx context.Context, ptmx gopty.Pty, distro string, spec ptySpec) *gopty.Cmd {
	cmd := ptmx.CommandContext(ctx, "wsl.exe", wslExecArgs(distro, spec.Command, spec.WorkDir, spec.Env)...)
	cmd.Env = withEnv(spec.Env)
	return cmd
}

// ptySupported reports whether a terminal can be provided: a Windows ConPTY is
// always available, so only an explicit global disable removes the capability.
func ptySupported() bool { return !InteractiveShellDisabled() }
