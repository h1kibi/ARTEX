package tool

import (
	"context"
	"path/filepath"
	"strings"

	gopty "github.com/aymanbagabas/go-pty"
)

// --- PTY launch ---

// ptySpec is everything a platform PTY backend needs to build its own process.
// A caller hands over the command (not an exec.Cmd) because the Windows backend
// must wrap it in `wsl.exe …`, a shape the caller cannot express.
type ptySpec struct {
	// Ctx bounds the child's lifetime: cancelling it kills the process, which is
	// how Manager.Close tears down live sessions.
	Ctx     context.Context
	Command string
	WorkDir string
	Env     []string
	Rows    int
	Cols    int
}

// ptyProc pairs the launched process with the master side of its terminal.
type ptyProc struct {
	cmd  *gopty.Cmd // process to Wait() on
	ptmx gopty.Pty  // terminal master: read output, write input
}

// wslWorkDir reports the Linux cwd for a Windows workDir under mountRoot, or ""
// when the path is not convertible (empty / relative).
func wslWorkDir(workDir, mountRoot string) string {
	d := toWSLPathWithRoot(workDir, mountRoot)
	if strings.HasPrefix(d, "/") {
		return d
	}
	return ""
}

// ptyWorkDir is a convenience for tests and non-Windows backends: the absolute
// form of workDir (empty stays empty so the child inherits the cwd).
func ptyWorkDir(workDir string) string {
	if workDir == "" {
		return ""
	}
	if abs, err := filepath.Abs(workDir); err == nil {
		return abs
	}
	return workDir
}
