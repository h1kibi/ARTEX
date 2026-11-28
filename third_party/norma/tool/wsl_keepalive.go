package tool

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// WSL2 suspends a distro shortly after its last process exits. Without a
// long-lived process the next command pays a cold start, and a session that
// idles for a few seconds can lose its terminal. One `sleep infinity` per distro
// keeps the VM warm; it is silent and consumes no CPU.
//
// NORMA_WSL_KEEPALIVE=0 (or false/off) disables the background process entirely.

// WSLKeepaliveEnv turns the background keepalive off.
const WSLKeepaliveEnv = "NORMA_WSL_KEEPALIVE"

type keepaliveProc struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	exited bool
}

var keepaliveProcs sync.Map // distro → *keepaliveProc

// wslKeepaliveDisabled reports whether the operator turned the keepalive off.
func wslKeepaliveDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(WSLKeepaliveEnv))) {
	case "0", "false", "off":
		return true
	}
	return false
}

// ensureWSLKeepalive makes sure a silent `sleep infinity` runs inside distro. It
// is idempotent: an already running process is left alone, an exited one is
// replaced.
func ensureWSLKeepalive(distro string) {
	if distro == "" || runtime.GOOS != "windows" || wslKeepaliveDisabled() {
		return
	}
	v, _ := keepaliveProcs.LoadOrStore(distro, &keepaliveProc{})
	k := v.(*keepaliveProc)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cmd != nil && !k.exited {
		return
	}
	cmd := exec.Command("wsl.exe", "-d", distro, "-e", "sh", "-c", "exec sleep infinity")
	cmd.SysProcAttr = hiddenWindowAttr()
	if err := cmd.Start(); err != nil {
		k.cmd = nil
		return
	}
	k.cmd = cmd
	k.exited = false
	go func() {
		_ = cmd.Wait()
		k.mu.Lock()
		if k.cmd == cmd {
			k.exited = true
		}
		k.mu.Unlock()
	}()
}

// CloseWSLKeepalives terminates every background keepalive process. The manager
// calls it during shutdown so no wsl.exe survives the server.
func CloseWSLKeepalives() {
	keepaliveProcs.Range(func(key, value any) bool {
		k := value.(*keepaliveProc)
		k.mu.Lock()
		cmd := k.cmd
		k.cmd = nil
		k.exited = true
		k.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		keepaliveProcs.Delete(key)
		return true
	})
}
