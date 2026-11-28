package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
)

// catastrophicBash matches a small set of irreversibly destructive commands
// that are hard-denied regardless of mode (NFR-10). This is a safety floor, not
// a full sandbox — hosts should still gate Bash via CanUseTool.
var catastrophicBash = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/(\s|$)`), // rm -rf /
	regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`),                               // fork bomb
	regexp.MustCompile(`\bmkfs\.\w+\s+/dev/`),                                                      // format a device
	regexp.MustCompile(`\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd)`),                                       // overwrite a disk
}

// ShellDialectNote describes the shell that actually runs Bash commands on this
// host. On a Windows host without an active WSL backend that is PowerShell, whose
// syntax differs from POSIX in ways a model will otherwise get wrong; elsewhere
// the tool prompt already describes bash, so the note is empty.
func ShellDialectNote(wslActive bool) string {
	if runtime.GOOS != "windows" || wslActive {
		return ""
	}
	return "当前命令在本机 Windows PowerShell 中执行：控制台输入输出已设为无 BOM 的 UTF-8；`curl`、`python`、`ssh` 直接调用本机程序；多条命令使用 `;` 串联，屏蔽错误输出使用 `2>$null`；多行或复杂逻辑使用 Write 工具写入 `.py` 脚本后执行 `python script.py`。不要使用 POSIX 的 `<<'EOF'` 或 `/dev/null`。"
}

// NewBash builds the Bash tool: run a shell command with a timeout, optionally in
// the background.
func NewBash() CoreTool {
	props := map[string]any{
		"command":    map[string]any{"type": "string", "description": "The shell command to execute."},
		"timeout_ms": map[string]any{"type": "integer", "description": "Timeout in ms (default 120000, max 600000)."},
	}
	desc := "Executes a shell command in the working directory and returns combined stdout and stderr. Use for running tests, builds, package managers, and git. Prefer the dedicated file tools for file work."
	prompt := "The command runs through the shell, so you are not limited to one command: chain steps with && or ;, use pipes, and pass multi-line scripts or heredocs. For anything beyond a simple one-liner — loops, parsing, string/JSON handling, HTTP logic, computation — prefer writing a short script (Python, Node, shell, etc.) and executing it (e.g. via a heredoc or by writing a file then running it) rather than forcing everything into a single command. A timeout (default 120s, max 600s) applies. Avoid commands needing interactive input."
	if !BackgroundTasksDisabled() {
		props["run_in_background"] = map[string]any{
			"type":        "boolean",
			"description": "Run in the background and return immediately; read its output later with TaskOutput or Read, and you are notified when it completes.",
		}
		desc += " Set run_in_background to return immediately and read the output later."
	}
	return Build(Spec{
		Name:        "Bash",
		Description: desc,
		Prompt:      prompt,
		Schema: map[string]any{
			"type":       "object",
			"properties": props,
			"required":   []any{"command"},
		},
		Permissions: bashPermissions,
		Run:         runBash,
	})
}

func bashPermissions(_ context.Context, input json.RawMessage, _ permission.Context) permission.Decision {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	for _, re := range catastrophicBash {
		if re.MatchString(in.Command) {
			return permission.Denied("denied: command appears irreversibly destructive and is blocked by the safety floor")
		}
	}
	return permission.AskUser("run shell command: " + in.Command)
}

func runBash(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error) {
	var in struct {
		Command         string `json:"command"`
		TimeoutMS       int    `json:"timeout_ms"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return Errorf("Error: command is required"), nil
	}
	timeout := 120 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
	}

	// Background-capable path: requires a task manager on the context.
	if tc != nil && tc.Tasks != nil && !BackgroundTasksDisabled() {
		return runBashManaged(ctx, tc, in.Command, timeout, in.RunInBackground)
	}
	// Fallback: synchronous execution (unchanged legacy behavior).
	return runBashSync(ctx, tc, in.Command, timeout)
}

// runBashManaged runs the command through the task manager, supporting explicit
// background launch; a foreground command that times out is killed with its
// process tree and reported as an error.
func runBashManaged(ctx context.Context, tc *ToolContext, command string, timeout time.Duration, explicitBG bool) (Result, error) {
	spec := SpawnSpec{Command: command, Kind: KindBash, WorkingDir: tc.WorkingDir, Description: short(command), Env: tc.Env}

	if explicitBG {
		t, err := tc.Tasks.Spawn(spec)
		if err != nil {
			return Errorf("Error: failed to start background command: " + err.Error()), nil
		}
		tc.Tasks.Background(t.ID)
		return Text(fmt.Sprintf(
			"Running in background as %s. Output file: %s\nUse TaskOutput{task_id:%q} or Read to read its output; you are notified when it completes.",
			t.ID, t.OutputPath, t.ID)), nil
	}

	t, finished, output, err := tc.Tasks.RunForeground(ctx, spec, timeout)
	if err != nil {
		if t != nil {
			tc.Tasks.Forget(t.ID)
		}
		return Errorf("Error: " + err.Error()), nil
	}
	if finished {
		info, _ := tc.Tasks.Get(t.ID)
		tc.Tasks.Forget(t.ID)
		if info.Status == TaskFailed {
			if strings.TrimSpace(output) == "" {
				output = "(no output)"
			}
			return Errorf(fmt.Sprintf("%s\n\n[exit code %d]", Capture(tc, output), info.ExitCode)), nil
		}
		if strings.TrimSpace(output) == "" {
			output = "(command produced no output)"
		}
		return Text(Capture(tc, output)), nil
	}

	// Timed out while still running: kill the whole tree and report what the
	// command produced before the deadline. Nothing is left running in the
	// background, since only an explicit request may start a background task.
	out, _ := tc.Tasks.Output(t.ID, 0)
	tc.Tasks.Kill(t.ID)
	tc.Tasks.Forget(t.ID)
	return Errorf(Capture(tc, out) + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
}

// runBashSync is the original blocking implementation, used when no task manager
// is available (background execution disabled).
func runBashSync(ctx context.Context, tc *ToolContext, command string, timeout time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var workDir string
	var env []string
	if tc != nil {
		workDir, env = tc.WorkingDir, tc.Env
	}
	cmd, viaWSL := shellProcess(cctx, command, workDir, env)
	var buf bytes.Buffer
	if viaWSL {
		// wsl.exe prints its own NAT/proxy diagnostics to stderr in UTF-16; the
		// filter drops those so a successful command does not come back wrapped
		// in mojibake.
		f := newWSLNoiseFilter(&buf)
		cmd.Stdout, cmd.Stderr = f, f
		err := cmd.Run()
		_ = f.Close()
		return finishSyncBash(tc, &buf, err, cctx, timeout)
	}
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return finishSyncBash(tc, &buf, err, cctx, timeout)
}

// finishSyncBash turns a finished synchronous run into a tool result: timeout
// first (a killed child also reports an error), then the exit status, then the
// success path, with Capture applied once at the end.
func finishSyncBash(tc *ToolContext, buf *bytes.Buffer, err error, cctx context.Context, timeout time.Duration) (Result, error) {
	out := Capture(tc, buf.String())
	if cctx.Err() == context.DeadlineExceeded {
		return Errorf(out + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if out == "" {
				out = "(no output)"
			}
			return Errorf(fmt.Sprintf("%s\n\n[exit code %d]", out, ee.ExitCode())), nil
		}
		return Errorf(fmt.Sprintf("%s\n\n[failed to run: %v]", out, err)), nil
	}
	if strings.TrimSpace(out) == "" {
		out = "(command produced no output)"
	}
	return Text(out), nil
}
