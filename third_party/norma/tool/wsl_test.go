package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestToWSLPath(t *testing.T) {
	cases := map[string]string{
		`C:\workspace\project`:                     "/mnt/c/workspace/project",
		`C:/workspace/project`:                     "/mnt/c/workspace/project",
		`D:\var\artex\tasks\12\i34`:                "/mnt/d/var/artex/tasks/12/i34",
		`c:\`:                                      "/mnt/c",
		`/already/posix`:                           "/already/posix",
		`relative\dir`:                             "relative/dir",
		``:                                         "",
		`\\server\share\x` /* UNC: best-effort */ : "//server/share/x",
	}
	for in, want := range cases {
		if got := toWSLPath(in); got != want {
			t.Errorf("toWSLPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A distro can automount drives at "/" (C: appears as /c) or at /mnt
// (C: appears as /mnt/c). The path conversion follows the probed layout.
func TestToWSLPathWithRoot(t *testing.T) {
	cases := []struct{ in, root, want string }{
		{`C:\workspace\dir with space`, "/mnt", "/mnt/c/workspace/dir with space"},
		{`C:\workspace\dir with space`, "/", "/c/workspace/dir with space"},
		{`C:\`, "/", "/c"},
		{`D:\var\artex`, "", "/mnt/d/var/artex"},
		{`/already/posix`, "/", "/already/posix"},
	}
	for _, c := range cases {
		if got := toWSLPathWithRoot(c.in, c.root); got != c.want {
			t.Errorf("toWSLPathWithRoot(%q, %q) = %q, want %q", c.in, c.root, got, c.want)
		}
	}
}

// Container runtimes register hidden distributions. Selecting one as the Linux
// backend leaves the operator without a usable shell and breaks drive paths.
func TestWSLInternalDistrosFiltered(t *testing.T) {
	for _, name := range []string{"docker-desktop", "Docker-Desktop-Data", "rancher-desktop-data", "podman-machine-default", "docker-desktop-proxy"} {
		if !wslInternalDistro(name) {
			t.Errorf("wslInternalDistro(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Ubuntu-22.04", "kali-linux", "Debian", "Alpine", "Ubuntu"} {
		if wslInternalDistro(name) {
			t.Errorf("wslInternalDistro(%q) = true, want false", name)
		}
	}
}

// Under mirrored networking the guest shares the host loopback, so a loopback
// proxy needs no rewriting and no gateway route.
func TestWSLProxyMirroredKeepsLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	raw := "http://127.0.0.1:" + port
	got, ok := wslProxyValueForGuest(raw, wslGuestInfo{mirrored: true, gateway: "192.0.2.1", mountRoot: "/mnt"})
	if !ok || got != raw {
		t.Fatalf("mirrored proxy = %q,%v; want %q unchanged", got, ok, raw)
	}
}

func TestWSLDistroFromEnv(t *testing.T) {
	cases := []struct {
		env  []string
		want string
	}{
		{nil, ""},
		{[]string{"NORMA_WSL_DISTRO=kali-linux"}, "kali-linux"},
		{[]string{"NORMA_WSL_DISTRO= kali-linux "}, "kali-linux"},
		{[]string{"NORMA_WSL_DISTRO=off"}, ""},
		{[]string{"NORMA_WSL_DISTRO=0"}, ""},
		{[]string{"NORMA_WSL_DISTRO=a", "NORMA_WSL_DISTRO=b"}, "b"}, // last wins, like exec
		{[]string{"HTTP_PROXY=http://x"}, ""},
	}
	for _, c := range cases {
		if got := wslDistroFromEnv(c.env); got != c.want {
			t.Errorf("wslDistroFromEnv(%v) = %q, want %q", c.env, got, c.want)
		}
	}
}

func TestWSLEnvArgsPassesProxyAndConvertsCAPaths(t *testing.T) {
	args := wslEnvArgs([]string{
		"HTTP_PROXY=http://127.0.0.1:8788",
		"HTTPS_PROXY=http://127.0.0.1:8788",
		`SSL_CERT_FILE=C:\Users\operator\AppData\Local\artex\mitm-ca.pem`,
		"REQUESTS_CA_BUNDLE=C:/Users/operator/ca.pem",
		"UNRELATED=drop-me",
		"NORMA_WSL_DISTRO=kali-linux",
	}, wslGuestInfo{gateway: "", mountRoot: "/mnt"})
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"SSL_CERT_FILE=/mnt/c/Users/operator/AppData/Local/artex/mitm-ca.pem",
		"REQUESTS_CA_BUNDLE=/mnt/c/Users/operator/ca.pem",
		"PAGER=cat", // non-interactive defaults always apply
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("wslEnvArgs missing %q in:\n%s", want, joined)
		}
	}
	for _, drop := range []string{"UNRELATED", "NORMA_WSL_DISTRO"} {
		if strings.Contains(joined, drop) {
			t.Errorf("wslEnvArgs must not forward %q:\n%s", drop, joined)
		}
	}
}

// A loopback proxy is unreachable from inside WSL2 (the guest's 127.0.0.1 is its
// own loopback). It must be re-pointed at a host address, and only when something
// actually listens there.
func TestWSLEnvArgsRewritesLoopbackProxyToGateway(t *testing.T) {
	// Stand in for the traffic WSL bridge: a listener on the "host" address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	hostAddr := "127.0.0.1"

	args := wslEnvArgs([]string{"HTTP_PROXY=http://127.0.0.1:" + port + "/"}, wslGuestInfo{gateway: hostAddr})
	want := "HTTP_PROXY=http://127.0.0.1:" + port + "/"
	found := false
	for _, kv := range args {
		if kv == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("reachable loopback proxy not rewritten to the host address: %v", args)
	}

	// A non-loopback proxy address is never rewritten.
	args = wslEnvArgs([]string{"HTTP_PROXY=http://10.9.9.9:3128"}, wslGuestInfo{gateway: hostAddr})
	for _, kv := range args {
		if strings.HasPrefix(kv, "HTTP_PROXY=") && kv != "HTTP_PROXY=http://10.9.9.9:3128" {
			t.Fatalf("non-loopback proxy rewritten: %q", kv)
		}
	}
}

// TestWSLEnvArgsDropsUnreachableLoopbackProxy is the critical regression from the
// real-machine run: a host address with NOTHING listening on the proxy port means
// the rewrite would produce 172.20.16.1:8788 → "connection refused" for every
// command. Neither that value nor the raw 127.0.0.1 may be exported; the variable
// must be left out entirely.
func TestWSLEnvArgsDropsUnreachableLoopbackProxy(t *testing.T) {
	deadPort := freePort(t)

	// Bridge absent (or not started) at the gateway address.
	for _, hostAddr := range []string{"127.0.0.1", ""} {
		args := wslEnvArgs([]string{
			"HTTP_PROXY=http://127.0.0.1:" + deadPort,
			"HTTPS_PROXY=http://127.0.0.1:" + deadPort,
			"ALL_PROXY=http://127.0.0.1:" + deadPort,
			"SSL_CERT_FILE=/tmp/ca.pem",
		}, wslGuestInfo{gateway: hostAddr, mountRoot: "/mnt"})
		for _, kv := range args {
			if isProxyVar(envKey(kv)) {
				t.Fatalf("unreachable loopback proxy must not be exported (hostAddr=%q): %q", hostAddr, kv)
			}
		}
		// Everything else still flows through.
		if !strings.Contains(strings.Join(args, "\n"), "SSL_CERT_FILE=/tmp/ca.pem") {
			t.Fatalf("non-proxy vars must survive (hostAddr=%q): %v", hostAddr, args)
		}
	}
}

// TestWSLProxyValueNonLoopbackAlwaysPasses: a LAN egress proxy needs no probe and
// no rewrite.
func TestWSLProxyValueNonLoopbackAlwaysPasses(t *testing.T) {
	for _, raw := range []string{"http://10.9.9.9:3128", "socks5://proxy.lan:1080"} {
		got, ok := wslProxyValue(raw, "")
		if !ok || got != raw {
			t.Fatalf("wslProxyValue(%q) = %q,%v; want unchanged", raw, got, ok)
		}
	}
	// A loopback proxy with no port cannot be re-pointed → dropped.
	if _, ok := wslProxyValue("http://127.0.0.1", "127.0.0.1"); ok {
		t.Fatal("a portless loopback proxy must be dropped")
	}
}

// freePort returns a port that is free right now (nothing listening).
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	return port
}

// wsl.exe writes its diagnostics to stderr as UTF-16LE. They must be decoded and
// dropped, while real command output (UTF-8) survives untouched.
func TestWSLNoiseFilterDropsWSLDiagnostics(t *testing.T) {
	var out bytes.Buffer
	f := newWSLNoiseFilter(&out)

	noise := utf16.Encode([]rune("wsl: 检测到 localhost 代理配置，但未镜像到 WSL。NAT 模式下的 WSL 不支持 localhost 代理。\r\n"))
	utf16le := make([]byte, 0, len(noise)*2)
	for _, u := range noise {
		utf16le = append(utf16le, byte(u), byte(u>>8))
	}
	if _, err := f.Write(utf16le); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("uid=0(root) gid=0(root)\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("tail-without-newline")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if strings.Contains(got, "wsl:") || strings.Contains(got, "\x00") {
		t.Fatalf("wsl.exe diagnostics leaked into output: %q", got)
	}
	if !strings.Contains(got, "uid=0(root) gid=0(root)") {
		t.Fatalf("real output lost: %q", got)
	}
	if !strings.Contains(got, "tail-without-newline") {
		t.Fatalf("trailing partial line lost: %q", got)
	}
}

// TestShellProcessLocalPathUnchanged pins the local path: without
// NORMA_WSL_DISTRO the child is the platform shell with its flags, and the
// command carries the local-shell initialization prefix.
func TestShellProcessLocalPathUnchanged(t *testing.T) {
	cmd, viaWSL := shellProcess(context.Background(), "echo hi", "", nil)
	if viaWSL {
		t.Fatal("must not select the WSL backend without NORMA_WSL_DISTRO")
	}
	shell, flags := shellCmd()
	if cmd.Path != shell && !strings.HasSuffix(strings.ToLower(cmd.Path), strings.ToLower(shell)+".exe") {
		t.Fatalf("cmd.Path = %q, want the platform shell %q", cmd.Path, shell)
	}
	args := cmd.Args[1:]
	if len(args) != len(flags)+1 || strings.Join(args[:len(flags)], " ") != strings.Join(flags, " ") {
		t.Fatalf("cmd args = %v, want %v + command", args, flags)
	}
	if want := wrapLocalShellCommand("echo hi"); args[len(args)-1] != want {
		t.Fatalf("command = %q, want %q", args[len(args)-1], want)
	}
}

func TestShellProcessSelectsWSL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL backend is Windows-only")
	}
	cmd, viaWSL := shellProcess(context.Background(),
		`echo "$HTTP_PROXY"`, `C:\workspace\x`, []string{"NORMA_WSL_DISTRO=kali-linux", "HTTP_PROXY=http://127.0.0.1:8788"})
	if !viaWSL {
		t.Fatal("NORMA_WSL_DISTRO on Windows must select the WSL backend")
	}
	joined := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-d kali-linux", "--cd /mnt/c/workspace/x", "-e env", "bash -lc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("wsl command missing %q: %s", want, joined)
		}
	}
}

// TestBashRunsInsideWSLWhenConfigured drives a real WSL distro end to end: the
// command is Linux shell syntax that PowerShell cannot parse, and the working
// directory arrives as its /mnt/... form.
func TestBashRunsInsideWSLWhenConfigured(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL backend is Windows-only")
	}
	distro := defaultWSLDistro()
	if distro == "" {
		t.Skip("no WSL distro installed")
	}
	t.Cleanup(CloseWSLKeepalives)
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{
		"command": `if [ -d "$PWD" ]; then echo "cwd-ok"; fi; echo "err-to-devnull" 2>/dev/null; echo "distro=$WSL_DISTRO_NAME"`,
	})
	tc := &ToolContext{WorkingDir: dir, Env: []string{"NORMA_WSL_DISTRO=" + distro}}
	res, err := NewBash().Call(context.Background(), raw, tc)
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	out := res.Flatten()
	if res.IsError {
		t.Fatalf("WSL-backed bash failed: %s", out)
	}
	for _, want := range []string{"cwd-ok", "err-to-devnull", "distro=" + distro} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// The Windows path must have been mapped, not passed to wsl.exe as-is.
	if strings.Contains(out, `C:\`) {
		t.Errorf("Windows path leaked into WSL output: %s", out)
	}
}

// TestWSLPTYSession drives the Windows PTY backend end to end: shell_open must
// succeed on a Windows box with WSL (it used to fail 100% of the time), and the
// program must see a real terminal, not a pipe.
func TestWSLPTYSession(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the WSL PTY bridge is Windows-only")
	}
	if !ptySupported() {
		t.Skip("no WSL distro available")
	}
	m, err := NewManager("test-wsl-pty")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()
	defer CloseWSLKeepalives()

	// `tty` prints a device path only when attached to a terminal.
	s, err := m.openSession(`tty; echo marker-$((1+1))`, "", nil, 24, 80, "hands-free", nil)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out, _, _ = s.readSince(0, 0, 8192, true)
		if strings.Contains(out, "marker-2") {
			if !strings.Contains(out, "/dev/pts/") {
				t.Fatalf("program did not get a real terminal, output:\n%s", out)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected PTY output, got %q", out)
}

// TestWSLPTYEcho proves the session is bidirectional through the bridge.
func TestWSLPTYEcho(t *testing.T) {
	if runtime.GOOS != "windows" || !ptySupported() {
		t.Skip("needs a Windows PTY backend")
	}
	m, err := NewManager("test-wsl-echo")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()
	defer CloseWSLKeepalives()
	s, err := m.openSession("cat", "", nil, 24, 80, "hands-free", nil)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if _, err := s.ptmx.Write([]byte("hello-pty\r")); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out, _, _ = s.readSince(0, 0, 8192, true)
		if strings.Contains(out, "hello-pty") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected echoed input, got %q", out)
}

// TestBackgroundTaskRunsInsideWSL: a run moved to the background must stay on the
// WSL backend (otherwise a Linux command suddenly runs under PowerShell), and the
// output file a later TaskOutput reads must be free of wsl.exe's diagnostics.
func TestBackgroundTaskRunsInsideWSL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL backend is Windows-only")
	}
	distro := defaultWSLDistro()
	if distro == "" {
		t.Skip("no WSL distro installed")
	}
	m, err := NewManager("test-wsl-bg")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()
	defer CloseWSLKeepalives()

	task, err := m.Spawn(SpawnSpec{
		Command: `echo "bg-ok" 2>/dev/null; echo "distro=$WSL_DISTRO_NAME"`,
		Kind:    KindBash, Env: []string{"NORMA_WSL_DISTRO=" + distro},
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		info, _ := m.Get(task.ID)
		out, _ = m.Output(task.ID, 0)
		if info.Status != TaskRunning {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out, "bg-ok") || !strings.Contains(out, "distro="+distro) {
		t.Fatalf("background WSL task produced %q", out)
	}
	if strings.Contains(out, "wsl:") {
		t.Fatalf("wsl.exe diagnostics reached the output file: %q", out)
	}
}

// TestHostReachableNegativeCacheIsShort: the traffic bridge comes up in a
// goroutine, so an early probe can legitimately miss it. A negative answer must
// therefore expire quickly (2s), unlike a positive one (30s) — otherwise a run's
// first command would drop the proxy for the rest of the window.
func TestHostReachableNegativeCacheIsShort(t *testing.T) {
	port := freePort(t)
	proxyProbeCache.Delete("127.0.0.1:" + port)
	if hostReachable("127.0.0.1", port) {
		t.Fatal("nothing listens on a freshly freed port")
	}
	v, ok := proxyProbeCache.Load("127.0.0.1:" + port)
	if !ok {
		t.Fatal("negative probe was not cached at all")
	}
	if got := v.(proxyProbe).ttl; got != proxyProbeNegTTL {
		t.Fatalf("negative TTL = %v, want %v", got, proxyProbeNegTTL)
	}
	if proxyProbeNegTTL >= proxyProbeTTL {
		t.Fatal("a negative probe must expire sooner than a positive one")
	}
}

// An explicit disable must be distinguishable from "the caller said nothing":
// only the latter may fall back to the machine's default distro. Without this an
// operator who turned WSL off still got WSL-backed PTYs and commands.
func TestWSLDistroDisabledInEnv(t *testing.T) {
	cases := []struct {
		env  []string
		want bool
	}{
		{nil, false},
		{[]string{"HTTP_PROXY=http://x"}, false},
		{[]string{"NORMA_WSL_DISTRO=kali-linux"}, false},
		{[]string{"NORMA_WSL_DISTRO=off"}, true},
		{[]string{"NORMA_WSL_DISTRO=0"}, true},
		{[]string{"NORMA_WSL_DISTRO=disabled"}, true},
		{[]string{"NORMA_WSL_DISTRO=FALSE"}, true},
		{[]string{"NORMA_WSL_DISTRO=off", "NORMA_WSL_DISTRO=kali-linux"}, false}, // last wins
		{[]string{"NORMA_WSL_DISTRO=kali-linux", "NORMA_WSL_DISTRO=off"}, true},
	}
	for _, c := range cases {
		if got := wslDistroDisabledInEnv(c.env); got != c.want {
			t.Errorf("wslDistroDisabledInEnv(%v) = %v, want %v", c.env, got, c.want)
		}
	}
}

// An explicit WSL disable must keep the PTY usable on a plain Windows host: the
// backend launches the local shell inside a native ConPTY instead of inventing a
// WSL session or failing outright.
func TestStartPTYRefusesExplicitWSLDisable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows ConPTY backend is Windows-only")
	}
	proc, err := startPTY(ptySpec{
		Ctx: context.Background(), Command: "echo pty-local-ok",
		Env: []string{WSLDistroEnv + "=off"},
	})
	if err != nil {
		t.Fatalf("startPTY with WSL disabled: %v", err)
	}
	defer func() {
		if proc.cmd != nil && proc.cmd.Process != nil {
			treeKill(proc.cmd.Process)
		}
		_ = proc.ptmx.Close()
	}()
	deadline := time.Now().Add(20 * time.Second)
	var out strings.Builder
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := proc.ptmx.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if strings.Contains(out.String(), "pty-local-ok") {
			return
		}
		if err != nil {
			t.Fatalf("read: %v (output %q)", err, out.String())
		}
	}
	t.Fatalf("local PTY produced no output: %q", out.String())
}

// A custom automount root must survive parsing unchanged: /etc/wsl.conf can move
// the drive mounts to /drives or collapse them onto a single drive root.
func TestParseWSLGuestProbeMountRoots(t *testing.T) {
	cases := map[string]string{
		"/mnt/c":       "/mnt",
		"/c":           "/",
		"/drives/c":    "/drives",
		"/windrives/d": "/windrives",
	}
	for mount, want := range cases {
		raw := []byte("MOUNT:" + want + "\nMIRROR:nat\nGW:172.20.16.1\n")
		info := parseWSLGuestProbe(raw)
		if info.mountRoot != want {
			t.Errorf("mount %q parsed root %q, want %q", mount, info.mountRoot, want)
		}
	}
}

func TestParseWSLGuestProbeNetworking(t *testing.T) {
	info := parseWSLGuestProbe([]byte("MOUNT:/mnt\nMIRROR:mirrored\nGW:10.0.0.1\n"))
	if !info.mirrored || info.gateway != "10.0.0.1" || info.mountRoot != "/mnt" {
		t.Fatalf("mirrored probe parsed as %+v", info)
	}
	info = parseWSLGuestProbe([]byte("MOUNT:/mnt\nMIRROR:nat\nGW:172.20.16.1\n"))
	if info.mirrored || info.gateway != "172.20.16.1" {
		t.Fatalf("nat probe parsed as %+v", info)
	}
	info = parseWSLGuestProbe([]byte("MIRROR:nat\n"))
	if info.mountRoot != "/mnt" {
		t.Fatalf("missing mount line changed the default root to %q", info.mountRoot)
	}
}
